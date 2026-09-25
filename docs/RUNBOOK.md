# SCBF Runbook — capturing, scanning and training

Practical guide to running the system. Every command here has been executed on
the reference VM (Ubuntu 26.04, kernel 7.0.0-34, Python 3.14 host / 3.11 target).

---

## ⚠️ Read this first

**Scanning a malicious package makes it actually run.** That is the whole point
of dynamic analysis — the payload has to execute for there to be behaviour to
observe. Consequences that were observed in practice during development:

- a benchmark sample planted an attacker SSH key in `~/.ssh/authorized_keys`,
  overwriting the file and locking the operator out;
- packages contact live attacker infrastructure from your IP;
- packages append lines to `~/.bashrc`.

**Only run this in a disposable VM.** Never on a machine that holds credentials,
never on your host, never on anything you plan to reuse for other work. Treat
the VM as compromised after the first malicious scan.

---

## 1. Prerequisites

Linux with eBPF. Capture will not run on macOS or Windows; *analysis* of an
already-captured trace is portable.

```bash
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) python3-venv git
```

Verify eBPF works before anything else:

```bash
sudo python3 -c "from bcc import BPF; print('bcc OK')"
```

If that fails, nothing downstream will work. Fix it first — usually a missing
`linux-headers` package for the running kernel.

### Target interpreter

The **host** Python runs the monitor; the **target** Python installs the package
under test. These are deliberately different.

Ubuntu 26.04 ships Python 3.14, on which many older real packages fail to build
(`configparser.SafeConfigParser` was removed in 3.12, `pkg_resources` in recent
setuptools). That failure rate is **class-correlated** — benign libraries break,
malware's trivial `setup.py` does not — which biases any dataset built with it.
Use Python 3.11 as the target:

```bash
pip install uv
uv python install 3.11
uv python find 3.11      # note the path; scan-live expects it
```

---

## 2. Setup

```bash
cd ~/scbf2
python3 -m venv .venv
.venv/bin/pip install -U pip numpy scikit-learn torch
```

Check the model and envelope loaded:

```bash
.venv/bin/python -c "
import sys; sys.path.insert(0,'.')
from scbf.detection.scan import Scanner
from pathlib import Path
s = Scanner(Path('models'))
print('WARN ', s.env['fused']['warn_threshold'])
print('BLOCK', s.env['fused']['block_threshold'])"
```

Expected: `WARN 7.754`, `BLOCK 8.894`.

---

## 3. Scan a package live  ← the common case

```bash
sudo ./scan-live <package-name | path-to-archive>
```

**A clean package, straight from PyPI:**

```bash
sudo ./scan-live requests
```

**A malicious sample:**

```bash
sudo ./scan-live data/raw/pypi_malware/etheraem-1.0.0.tar.gz
```

**Any local archive:**

```bash
sudo ./scan-live /path/to/package.tar.gz
```

What it does: restores a byte-identical venv from a template (pre-seeded with
`setuptools`, `wheel`, `requests`), runs `pip install` under the eBPF monitor,
then scores the resulting trace. The template matters — a bare venv fails every
sdist, and without `requests` a large share of PyPI malware raises
`ModuleNotFoundError` in `setup.py` and never executes its payload at all.

### Reading the output

```
[BLOCK]  scan_etheraem-1.0.0.jsonl
         threat score        : 93.3/100
         classifier p(malicious): 0.9706
         envelope distance   : 11.0588
         events              : 4812
           - wrote 4 file(s) outside the install target
```

| field | meaning |
|---|---|
| **verdict** | ALLOW / WARN / BLOCK from envelope distance, escalated by the classifier |
| **envelope distance** | Euclidean distance from the benign centroid. WARN ≥ 7.754, BLOCK ≥ 8.894 |
| **classifier p** | the hybrid TGN's own probability — an *independent* second opinion |
| **threat score** | 0 at the centroid, 75 at the BLOCK threshold, capped at 100 |
| **evidence** | behaviours observed, with installer/sandbox infrastructure excluded |

Typical observed values: **benign ≈ 4.8–5.5**, **malware ≈ 11–14.5**.

---

## 4. Scan traces you already have

Single trace:

```bash
.venv/bin/python -m scbf.detection.scan --trace /tmp/scan_requests.jsonl --models models
```

A whole directory:

```bash
.venv/bin/python -m scbf.detection.scan --batch data/traces/malware/traces --limit 20 --models models
```

Batch mode prints a verdict per trace and a summary count at the end.

---

## 5. Capture a trace without scoring it

```bash
sudo bash capture/monitor.sh <name> <venv-python> <artifact> <output.jsonl>
```

Writes one JSON record per event:

```json
{"type":"open","pid":1234,"ppid":1233,"comm":"python",
 "fname":"/home/u/.ssh/id_rsa","ts":27156180602024,"write":false,"flags":0}
{"type":"connect","pid":1234,"ppid":1233,"comm":"curl",
 "fname":"connect","daddr":"185.99.4.7","dport":4444,"ts":27156180657816}
```

Four tracepoints are attached: `sched_process_fork` (propagates tracking to
children in-kernel — without it short-lived `curl`/`sh` are missed entirely),
`execve`, `openat` (with flags, so writes are distinguishable from reads) and
`connect` (with the sockaddr, so destinations are recorded).

---

## 6. Rebuild the whole dataset and model

Only needed if you are re-collecting from scratch. Roughly 6 h capture + 2 h
training.

```bash
# 1. extract the benchmark archives
cd data/raw && unzip -q ~/Downloads/rq1_pypi_malware.zip && unzip -q ~/Downloads/rq1_pypi_benign.zip

# 2. capture BOTH classes in ONE interleaved run  (~6 h for 2,000 packages)
sudo python3 capture/collect_dataset.py \
    --benign  data/raw/pypi_benign \
    --malware data/raw/pypi_malware \
    --out     data/traces \
    --python  $(uv python find 3.11)

# 3. audit — this is a gate, not a report
.venv/bin/python -m scbf.audit.leakage --traces data/traces --strict

# 4. what is actually in the traces
.venv/bin/python -m scbf.audit.signal_report --traces data/traces

# 5. tabular baselines — the bar the TGN must clear
.venv/bin/python -m scbf.training.baseline --traces data/traces

# 6. train  (~2 h, ~3.5 min/epoch)
.venv/bin/python -m scbf.training.train --traces data/traces

# 7. evaluate
.venv/bin/python -m scbf.training.evaluate --traces data/traces

# 8. rebuild the envelope from the new model
.venv/bin/python -m scbf.envelope.build --traces data/traces --models models
```

`run_pipeline.sh` chains steps 3–7 and **stops at step 3 if the audit fails**.

### Why step 3 is not optional

The original benchmark capture contained a collection artefact: `/dev/pts`
appeared in 97.2 % of benign traces and 0 % of malicious ones, because the two
classes had been captured through different harness invocations. A one-line rule
on it scored **96.48 % F1**, and the model trained on that data collapsed from
**92.31 % to 52.53 % F1** once the artefact was removed.

The collector prevents this by construction — one shuffled queue, one harness,
no controlling terminal for either class — and the audit verifies it afterwards.
Do not report a number from a corpus that has not passed the audit.

### Interrupted capture

The collector is resumable. Re-run the identical command; packages already
recorded `ok` in `data/traces/manifest.jsonl` are skipped and the seeded
interleaving is preserved. `--restart` forces a full re-capture.

---

## 7. Interpreting a verdict honestly

**The model is good but not perfect** — 88.14 % recall on held out data, so
roughly 1 in 8 malicious packages is missed.

**A near-threshold score is not a reliable verdict.** Traces are not bit-identical
between runs (timing, dependency resolution, kernel version). The same
`etheraem-1.0.0` scored 14.21 in one capture and 11.06 in another. Both were
BLOCK, but a package sitting near 7.754 can flip between ALLOW and WARN.

**Install-time analysis cannot see runtime-only payloads.** `colorsama-0.4.5` is
a typosquat of `colorama` whose `setup.py` is a verbatim copy of the legitimate
one; the payload runs at *import*, not install. It scored 7.56 — just under WARN
— and was missed. No install-time method can catch this class of attack.

**Most malware here shows no obvious malicious indicator.** Measured strictly,
**81.2 %** of malicious traces contain no package-attributable suspicious action
(no `curl`, no external connection, no credential read, no persistence write).
The model separates the classes on distributed structural differences, the
clearest being that benign packages *install substance* — `rich` wrote 1,085
files, `etheraem` wrote 67. So an empty evidence list does not mean the verdict
is wrong, and a BLOCK is not a claim that a specific named attack occurred.

Treat the output as a prioritisation signal for review, not a proof.

---

## 8. Troubleshooting

| symptom | cause and fix |
|---|---|
| `from bcc import BPF` fails | install `python3-bpfcc` and `linux-headers-$(uname -r)` for the *running* kernel |
| monitor exits non-zero, 0 events | not running as root — eBPF requires it |
| every install fails, `Cannot import 'setuptools.build_meta'` | venv template missing; delete `/tmp/scbf_venv_template` and re-run |
| installs fail only for benign packages | target interpreter too new — use Python 3.11, not 3.14 |
| `Permission denied` writing into the venv | the monitor drops to `SUDO_USER`; `chown -R` the venv to that user |
| traces captured but no `exec` events | `sched_process_fork` probe not attached — check the probe compiles |
| audit reports leaking tokens | do **not** train. Fix the capture: both classes, one run, one harness |
| training OOM-killed | `/tmp` is tmpfs and consumes RAM — clear it, and add swap |
| verdict always ALLOW | `models/envelope.json` missing — run `scbf.envelope.build` |

---

## 9. File map

```
capture/monitor.sh              eBPF probes + JSONL writer
capture/collect_dataset.py      interleaved batch collection, resumable
scan-live                       install + scan in one command
scbf/graph/itbg.py              heterogeneous behaviour graph
scbf/models/tgn_encoder.py      GRU memory + learned time encoding
scbf/features/statistical.py    51 descriptors
scbf/audit/leakage.py           the gate
scbf/audit/signal_report.py     what is in the traces; recall ceiling
scbf/dataset.py                 manifest gate — excludes failed installs
scbf/training/train.py          training
scbf/training/evaluate.py       three-split metrics
scbf/training/baseline.py       LR / gradient-boosting baselines
scbf/training/cross_validate.py 5-fold CV, pooled out-of-fold
scbf/envelope/build.py          centroid + WARN/BLOCK thresholds
scbf/detection/scan.py          verdict engine
```

---

## 10. Current measured performance

Held-out test split, 210 traces (59 malicious), scored once:

| metric | value |
|---|---|
| Accuracy | 95.71 % |
| Precision | 96.30 % |
| Recall | 88.14 % |
| F1 | **92.04 %** |
| ROC-AUC | 0.9762 |

Train−test F1 gap +0.45 %. Dataset passes the leakage audit. Live validation on
seven freshly captured packages (three clean, never in the benchmark, installed
from PyPI on a different kernel; four held-out malicious) returned **6/7 correct**
— the miss being `colorsama`, described in §7.
