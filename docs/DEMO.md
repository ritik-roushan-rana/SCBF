# SCBF Demo — copy-paste commands

All commands run **on the Ubuntu VM**, in `~/scbf2`.

> ⚠️ **These packages really execute.** Only ever run them in the disposable VM.
> One benchmark sample planted an attacker SSH key in `~/.ssh/authorized_keys`
> during development. Never on your host, never anywhere holding credentials.

```bash
cd ~/scbf2
```

---

## 0. Three ways to run it

| command | what it does |
|---|---|
| `pip install <x>` | **intercepted automatically** — screened, then installed only if ALLOW |
| `sudo scbf-pip install <x>` | the gate, called explicitly |
| `sudo ./scan-live <x>` | scan only, never installs for real |

Verdict thresholds: **WARN ≥ 7.754**, **BLOCK ≥ 8.894**.
Typical: benign **4–5.5**, malware **11–14.5**.

---

## 1. Clean packages — expect ALLOW

```bash
pip install httpx
```

```bash
pip install tenacity
```

```bash
pip install loguru
```

Expected: `[ALLOW]`, distance ≈ 4–5.5, `p(malicious)` ≈ 0.003.

---

## 2. Malware — expect BLOCK

Strong, unambiguous detections (distance 14.0–14.4, threat 100/100):

```bash
pip install ~/scbf2/data/raw/pypi_malware/PyTorchy-1.0.0.tar.gz
```

```bash
pip install ~/scbf2/data/raw/pypi_malware/tensobflow-1.0.0.tar.gz
```

```bash
pip install ~/scbf2/data/raw/pypi_malware/playwrght-1.0.0.tar.gz
```

```bash
pip install ~/scbf2/data/raw/pypi_malware/requiremnetstxt-1.0.0.tar.gz
```

```bash
pip install ~/scbf2/data/raw/pypi_malware/etheraem-1.0.0.tar.gz
```

Closer to the threshold (distance 10.8–11.5, threat 91–97) — still blocked:

```bash
pip install ~/scbf2/data/raw/pypi_malware/rdquests-2.28.1.tar.gz
```

```bash
pip install ~/scbf2/data/raw/pypi_malware/flake7-4.5.2.tar.gz
```

---

## 3. The one it MISSES — show this too

```bash
pip install ~/scbf2/data/raw/pypi_malware/colorsama-0.4.5.tar.gz
```

Result: **`[ALLOW]` at distance 7.54** — a false negative, 0.2 below the WARN line.

`colorsama` is a typosquat of `colorama` whose `setup.py` is a **verbatim copy of
the legitimate one**, right down to the BSD licence header. Its payload runs at
*import*, not at install, so there is no install-time behaviour to observe. No
install-time method can catch this class of attack.

Demonstrate this alongside the successes. It is the honest illustration of the
88.14 % recall, and presenting it yourself is far more credible than having a
reviewer find it.

---

## 4. Override and bypass

Install despite a BLOCK:

```bash
sudo scbf-pip install ~/scbf2/data/raw/pypi_malware/colorsama-0.4.5.tar.gz --force
```

Skip the gate entirely for one command:

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

```
[BLOCK]  gate_PyTorchy-1.0.0.jsonl
         threat score        : 100.0/100
         classifier p(malicious): 0.9999
         envelope distance   : 14.1491
         events              : 5073
           - wrote 4 file(s) outside the install target
```

| field | meaning |
|---|---|
| **verdict** | from envelope distance, escalated by the classifier |
| **envelope distance** | distance from the benign centroid; WARN ≥ 7.754, BLOCK ≥ 8.894 |
| **classifier p** | the TGN's own probability — an independent second opinion |
| **threat score** | 0 at centroid, 75 at BLOCK threshold, capped at 100 |
| **evidence** | observed behaviours, installer/sandbox infrastructure excluded |

---

## 7. What to say when demoing

**What it does.** Captures install-time behaviour with eBPF, encodes it as a
temporal graph, and judges distance from a calibrated envelope of benign
installs. No signatures, no rules, no threat feed.

**Measured performance.** 92.04 % F1, 96.30 % precision, 88.14 % recall,
ROC-AUC 0.9762 on a held-out test split, on a dataset that passes a leakage
audit. Live-validated 6/7 on freshly captured unseen packages.

**Be upfront about the limits:**

- Roughly **1 in 8 malicious packages is missed** (`colorsama`).
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
