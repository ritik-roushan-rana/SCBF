# SCBF — Supply-Chain Behavioural Fingerprinting

Detects and **blocks malicious PyPI packages while they install**, from
install-time behaviour captured with eBPF and modelled as a temporal graph.
No signatures, no rules, no threat feed.

![SCBF architecture](docs/assets/architecture.png)

```
pip install <package>
        |
   eBPF capture       sched_process_fork . execve . openat+flags . connect+sockaddr
        |
   normalisation      installer/sandbox infrastructure removed
        |
   ITBG               typed temporal graph: process file network env credential script
        |
   TGN encoder        128-dim GRU memory per node + learned phi(dt) -> Behavioural DNA
        |
   fusion             8 DNA snapshots + 51 statistical features -> 192-dim
        |
   event 3000         score the PARTIAL graph  (~60% into a malicious install)
        |
   BLOCK -> SIGKILL the installer tree   |   ALLOW -> let it finish
```

---

## Results

### Install-time blocking (main result)

3-seed TGN ensemble, decision at event 3000. Threshold tuned on validation only;
test scored once.

| Split | n | Accuracy | Precision | Recall | F1 | ROC-AUC | TP/FN/FP/TN |
|---|---|---|---|---|---|---|---|
| Train | 974 | 94.56% | 91.01% | 89.34% | 90.17% | 0.9725 | 243/29/24/678 |
| Validation | 209 | 97.13% | 96.43% | 93.10% | 94.74% | 0.9862 | 54/4/2/149 |
| **Test** | **210** | **96.19%** | **93.22%** | **93.22%** | **93.22%** | **0.9839** | **55/4/4/147** |

Generalisation gap (train F1 - test F1) = -3.05%.

> Precision and recall coincide on the test split because false positives and
> false negatives are both 4; F1, their harmonic mean, equals both.

### Against published baselines (same PyPI benchmark)

| Tool | Precision | Recall | F1 | Latency |
|---|---|---|---|---|
| **SCBF (install-time)** | 93.22% | **93.22%** | **93.22%** | 2-5 s |
| OSCAR (ASE '24) | 99.00% | 85.00% | 91.00% | ~165 s |
| Guarddog | 89.00% | 94.00% | 91.00% | static |
| SAP | 73.00% | 86.00% | 79.00% | static |

**Recall +8.22, F1 +2.22 over OSCAR**, at ~30x lower latency, while *preventing*
execution rather than reporting after it.

Not like-for-like: OSCAR is zero-shot over all 500 malicious packages; SCBF is
supervised and scored on 59 held-out samples (+/-4% bootstrap CI).

### Post-install detection (secondary)

| | Precision | Recall | F1 |
|---|---|---|---|
| single split | 96.30% | 88.14% | 92.04% |
| **5-fold CV** (all 389 malicious) | 94.38% | 86.38% | **88.93% +/- 1.68%** |

### Live validation

7/7 malware blocked mid-install, 8/10 clean packages allowed. `numpy` and
`pandas` were the false positives - heavy compiled packages sit closest to the
decision boundary.

---

## Layout

```
capture/
  monitor.sh            eBPF probes -> JSONL
  guard.sh              LIVE GUARD: streams events, scores, kills mid-install
  collect_dataset.py    interleaved single-harness dataset collection

scbf/
  graph/itbg.py            heterogeneous temporal graph, capture-stable node ids
  models/tgn_encoder.py    GRU memory bank + learned time encoding
  features/statistical.py  51 behavioural descriptors
  audit/leakage.py         dataset gate - refuses to train on a leaking corpus
  audit/signal_report.py   what is in the traces; recall ceiling
  dataset.py               manifest gate - excludes failed installs
  training/                train, evaluate, baselines, cross-validation
  envelope/                benign centroid + WARN/BLOCK thresholds
  detection/               scan, threshold tuning, ensembles

models/
  blocker/              INSTALL-TIME: 3-seed ensemble, decision at event 3000
    seed42/ seed7/ seed1337/
    ensemble_results.json
  postinstall/          full-trace detection

data/traces/            manifest.jsonl + environment.json (traces gitignored)
docs/RUNBOOK.md         operating guide
docs/DEMO.md            copy-paste demo commands
```

---

## Usage

On the Linux VM (eBPF required):

```bash
pip install <package>            # intercepted; killed mid-install if malicious
sudo scbf-guard-pip install <x>  # same, explicit
SCBF_BYPASS=1 pip install <x>    # skip the guard
sudo rm /usr/local/bin/pip       # remove interception
```

Rebuild from scratch:

```bash
sudo python3 capture/collect_dataset.py --benign data/raw/pypi_benign \
     --malware data/raw/pypi_malware --out data/traces --python $(uv python find 3.11)
python3 -m scbf.audit.leakage --traces data/traces --strict
python3 -m scbf.training.train --traces data/traces --prefix 3000 --out models/blocker/seed42
python3 -m scbf.training.evaluate --traces data/traces --models models/blocker/seed42
```

See `docs/RUNBOOK.md` for the full procedure.

---

## Why the decision point is event 3000

Measured ROC-AUC by prefix length:

| first N events | 100 | 500 | 1000 | **1500** | 3000 |
|---|---|---|---|---|---|
| ROC-AUC | 0.508 | 0.497 | 0.432 | **0.957** | 0.979 |

The first ~1,400 events are pip's own resolve/download/unpack and are identical
for every package - deciding there is guessing. The package's `setup.py` starts
executing around event 1500, which is both when behaviour begins and when it
becomes detectable. Event 3000 is ~60% into a malicious install, trading a
little earliness for accuracy.

---

## Dataset integrity

The published benchmark contained a **collection artefact**: `/dev/pts` appeared
in 97.2% of benign traces and 0% of malicious ones, because the two classes had
been captured through different harness invocations.

| measurement on the original capture | F1 |
|---|---|
| one-line rule, "malicious if <5 /dev accesses" | 96.48% |
| trained model, artefact present | 92.31% |
| same model, artefact removed | **52.53%** |

Fixed by collecting both classes in one interleaved run through one harness with
no controlling terminal. `scbf/audit/leakage.py` gates training and refuses any
corpus where a token appears in >=90% of one class and <=10% of the other. The
corrected corpus (1,393 traces: 389 malicious / 1,004 benign) passes.

---

## Known limits

- **Import-time payloads are invisible.** `colorsama-0.4.5` is a typosquat whose
  `setup.py` is a verbatim copy of legitimate `colorama`; its payload runs at
  import. No install-time method catches this class.
- **81.2% of malicious traces show no obvious malicious action** - no `curl`, no
  external connection, no credential read. The model separates on distributed
  structure (benign packages install substance: `rich` wrote 1,085 files,
  `etheraem` 67), so a BLOCK is not a claim that a specific attack occurred.
- **Heavy compiled packages sit near the boundary** - `numpy` and `pandas` were
  live false positives.
- **The architecture is a TGN memory module** (GRU + learned time encoding), not
  Rossi et al.'s attention-based TGN. There is no neighbour-attention layer.
- **Evaluated on packages that install cleanly** under Linux/Python 3.11 -
  1,393 of 2,000. Malicious packages install more reliably (77.8% vs 66.9%)
  because they are structurally simpler.
