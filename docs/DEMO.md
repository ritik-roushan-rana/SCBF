# SCBF Demo — copy-paste commands

All commands run **on the Ubuntu VM**, in `~/scbf2`.

> ⚠️ **These packages really execute.** Only ever run them in the disposable VM.
> One benchmark sample planted an attacker SSH key in `~/.ssh/authorized_keys`
> during development. Never on your host, never anywhere holding credentials.

```bash
cd ~/scbf2
```

---

## 0. Two modes

**LIVE GUARD — blocks during installation** (this is the default for `pip`):

| command | what it does |
|---|---|
| `pip install <x>` | one install, monitored live, **killed mid-flight if malicious** |
| `sudo scbf-guard-pip install <x>` | the same, called explicitly |
| `SCBF_DRY_RUN=1 sudo scbf-guard-pip install <x>` | decides but never kills |

Decision at **event 3000** (~60% into a malicious install), on the averaged
probability of a **3-encoder ensemble**, **p ≥ 0.1925**. Measured on 210 held-out
traces: **precision 93.22%, recall 93.22%, F1 93.22%, ROC-AUC 0.9839**.

Nothing earlier is actionable — the first ~1,400 events are pip's own resolve,
download and unpack, identical for every package (ROC-AUC 0.508 at 100 events,
0.432 at 1000). Discrimination appears at ~1500, where the package's own
`setup.py` begins executing; event 3000 trades a little earliness for accuracy.

**POST-INSTALL GATE — sandbox first, then install** (the older path):

| command | what it does |
|---|---|
| `sudo scbf-pip install <x>` | installs in a sandbox, scores, then installs for real only if ALLOW |
| `sudo ./scan-live <x>` | scan only, never installs |

Thresholds there: WARN ≥ 7.754, BLOCK ≥ 8.894; benign 4–5.5, malware 11–14.5.

---

## 1. Clean packages — expect ALLOW (install completes)

```bash
pip install requests
pip install rich
pip install httpx
pip install loguru
pip install tenacity
pip install flask
pip install click
pip install jinja2
```

**Verified live** (ensemble probability at the decision point):

| package | p(malicious) | verdict |
|---|---|---|
| click | 0.0158 | ALLOW |
| jinja2 | 0.0164 | ALLOW |
| loguru | 0.0203 | ALLOW |
| httpx | 0.0233 | ALLOW |
| flask | 0.0270 | ALLOW |
| requests | 0.0298 | ALLOW |
| tenacity | 0.1163 | ALLOW |
| rich | 0.1670 | ALLOW |
| **numpy** | **0.1643** | **BLOCKED — false positive** |
| **pandas** | **0.1611** | **BLOCKED — false positive** |

8 of 10 correct. `numpy` and `pandas` are the realistic failure mode: large
packages with compiled extensions sit closest to the decision boundary.

---

## 2. Malware — the install is KILLED mid-flight

```bash
pip install ~/scbf2/data/raw/pypi_malware/PyTorchy-1.0.0.tar.gz
pip install ~/scbf2/data/raw/pypi_malware/etheriuum-1.0.0.tar.gz
pip install ~/scbf2/data/raw/pypi_malware/selenyum-1.0.0.tar.gz
pip install ~/scbf2/data/raw/pypi_malware/requiremenstx-1.0.0.tar.gz
pip install ~/scbf2/data/raw/pypi_malware/capmonsterclouddclient-1.0.0.tar.gz
pip install ~/scbf2/data/raw/pypi_malware/tensobflow-1.0.0.tar.gz
pip install ~/scbf2/data/raw/pypi_malware/asteroid_filterbank-0.4.0.tar.gz
```

**Verified live — 7 of 7 terminated:**

| package | p(malicious) | verdict |
|---|---|---|
| selenyum-1.0.0 | 0.9834 | BLOCKED |
| etheriuum-1.0.0 | 0.9628 | BLOCKED |
| tensobflow-1.0.0 | 0.9422 | BLOCKED |
| PyTorchy-1.0.0 | 0.9007 | BLOCKED |
| capmonsterclouddclient-1.0.0 | 0.8887 | BLOCKED |
| requiremenstx-1.0.0 | 0.6797 | BLOCKED |
| asteroid_filterbank-0.4.0 | 0.1119 | BLOCKED (later checkpoint) |

Expected output:

```
[guard] ensemble of 3 models
[guard] event 3000: p(malicious)=0.9007 distance=9.02 -> BLOCK
[guard] TERMINATING installer process tree (pid 4363) at event 3000
[+] VERDICT : BLOCKED — install terminated mid-flight
[!] INSTALLATION FAILED
```

---

## 3. The one it MISSES — show this too

```bash
pip install ~/scbf2/data/raw/pypi_malware/colorsama-0.4.5.tar.gz
```

Installs successfully — a false negative.

`colorsama` is a typosquat of `colorama` whose `setup.py` is a **verbatim copy of
the legitimate one**, right down to the BSD licence header. Its payload runs at
*import*, not at install, so there is no install-time behaviour to observe. No
install-time method can catch this class of attack.

Demonstrate it alongside the successes. It is the honest illustration of the
limits, and presenting it yourself is far more credible than having a reviewer
find it.

---

## 4. Override and bypass

Decide but never kill (useful for demos):

```bash
SCBF_DRY_RUN=1 sudo scbf-guard-pip install ~/scbf2/data/raw/pypi_malware/PyTorchy-1.0.0.tar.gz
```

Change the block threshold for one run:

```bash
SCBF_BLOCK_P=0.9 sudo scbf-guard-pip install ~/scbf2/data/raw/pypi_malware/PyTorchy-1.0.0.tar.gz
```

Skip the guard entirely for one command:

```bash
SCBF_BYPASS=1 pip install numpy
```

Remove the interception:

```bash
sudo rm /usr/local/bin/pip
```

---

## 5. Scan without installing

```bash
sudo ./scan-live requests
```

Re-scan a trace already captured:

```bash
.venv/bin/python -m scbf.detection.scan --trace /tmp/gate_numpy.jsonl --models models
```

Batch a whole directory:

```bash
.venv/bin/python -m scbf.detection.scan --batch data/traces/malware/traces --limit 20 --models models
```

---

## 6. Reading the output

**Live guard** (what `pip install` now prints):

```
[guard] event 1500: p(malicious)=0.8078 distance=6.303 -> BLOCK
[guard] TERMINATING installer process tree (pid 5296) at event 1500
[+] VERDICT : BLOCKED — install terminated mid-flight
```

| field | meaning |
|---|---|
| **event N** | the checkpoint at which this decision was taken |
| **p(malicious)** | the TGN's probability — **this drives the decision**, BLOCK at ≥ 0.685 |
| **distance** | envelope distance at that checkpoint — corroborating, not deciding |
| **verdict** | BLOCK kills the process tree; WARN is logged and the install continues |

**Post-install gate** (`scbf-pip` / `scan-live`) prints a different format, with
an envelope distance on the completed trace: WARN ≥ 7.754, BLOCK ≥ 8.894,
benign ≈ 4–5.5, malware ≈ 11–14.5, plus a threat score and evidence list.

---

## 7. What to say when demoing

**What it does.** Captures install-time behaviour with eBPF, encodes it as a
temporal graph, and judges distance from a calibrated envelope of benign
installs. No signatures, no rules, no threat feed.

**Measured performance.**

- *Install-time blocking* (main result): **precision 93.22%, recall 93.22%,
  F1 93.22%, ROC-AUC 0.9839** on a held-out test split, decision at event 3000.
  Beats OSCAR on recall (+8.22) and F1 (+2.22). Live-validated 7/7 malware
  terminated, 8/10 clean allowed.
- *Post-install detection*: 92.04% F1 single split; **88.93% ± 1.68%
  cross-validated** over all 389 malicious packages.
- The dataset passes the leakage audit.

**Be upfront about the limits:**

- Roughly **1 in 15 malicious packages is missed** on the held-out split
  (4 of 59), `colorsama` among them.
- **False positives on heavy compiled packages** — `numpy` and `pandas` were
  both blocked live. Precision on the benchmark's benign set (93.22%)
  overstates precision on large real-world packages.
- The install target is a throwaway venv (`/tmp/scbf_install_env`). Killing
  mid-install leaves a half-populated site-packages, so it has to be
  discardable. Pointing this at a real environment needs rollback handling,
  which does not exist yet.
- **The package still executes once**, inside the sandbox. The gate reports what
  it did; it does not prevent it from acting during that run. Only the VM
  isolates you.
- **81.2 % of malicious traces show no obvious malicious indicator** — no
  `curl`, no external connection, no credential read. The model separates the
  classes on distributed structure, largely that benign packages *install
  substance* (`rich` wrote 1,085 files; `etheraem` wrote 67). So a BLOCK is not
  a claim that a specific named attack occurred.
- **Near-threshold scores are not stable.** The same `etheraem` scored 14.21 in
  one capture and 11.06 in another. A package near 7.754 can flip between runs.
- Large scientific packages sit closer to the line (`numpy` scored 6.56), so
  false positives on heavy compiled packages are a realistic failure mode.

Treat the verdict as a prioritisation signal for review, not a proof.
