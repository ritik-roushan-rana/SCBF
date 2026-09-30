# SCBF Runbook — capturing, blocking and training

Practical guide to running the system. Every command here has been executed on
the reference VM (Ubuntu 26.04, kernel 7.0.0-34, Python 3.14 host / 3.11 target,
Node 22 / npm 9).

---

## ⚠️ Read this first

**Blocking a malicious package makes it actually run.** That is inherent to
dynamic analysis — the payload must execute for there to be behaviour to
observe, and the guard kills it *after* it has started. Consequences observed
during development:

- a benchmark sample planted an attacker SSH key in `~/.ssh/authorized_keys`,
  overwriting the file and locking the operator out;
- packages contact live attacker infrastructure from your IP;
- packages append lines to `~/.bashrc`.

**Only run this in a disposable VM.** Never on a machine holding credentials,
never on your host. Treat the VM as compromised after the first malicious run.

---

## 1. Prerequisites

Linux with eBPF. Capture will not run on macOS or Windows; *analysis* of an
already-captured trace is portable.

```bash
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) \
                    python3-venv git curl net-tools dnsmasq
sudo python3 -c "from bcc import BPF; print('bcc OK')"
```

If that last line fails nothing downstream works — usually a missing
`linux-headers` for the running kernel.

### Target interpreter

The **host** Python runs the monitor; the **target** Python installs the package
under test. These are deliberately different.

Ubuntu 26.04 ships Python 3.14, on which many older real packages fail to build
(`configparser.SafeConfigParser` removed in 3.12). That failure rate is
**class-correlated** — benign libraries break, malware's trivial `setup.py` does
not — which biases any dataset built with it. Measured: 63.3% benign vs 77.6%
malware success. Use Python 3.11 as the target:

```bash
pip install uv && uv python install 3.11 && uv python find 3.11
```

### Network containment

Malicious packages exfiltrate. The reference VM contains this without breaking
the package registries:

```bash
# everything resolves to a sinkhole on a dummy interface EXCEPT the registries
cat /etc/dnsmasq.d/scbf-sinkhole.conf
#   server=/pypi.org/<upstream>         server=/registry.npmjs.org/<upstream>
#   server=/pythonhosted.org/<upstream> server=/npmjs.org/<upstream>
#   address=/#/203.0.113.1

systemctl status scbf-sinkhole-iface    # creates 203.0.113.1 on dummy0
systemctl status scbf-sink              # answers 200 on :80 and :443
```

**The sinkhole address must not be `127.0.0.1`.** The feature extractor counts a
contact as external only when it is off loopback/RFC1918, so sinking to
localhost zeroes `n_ext_connect` for every package and hides the strongest
malicious signal. With that misconfiguration the guard allowed known malware at
p=0.0000.

**A local sink must answer**, otherwise `curl` exits 7, the hook fails, npm
aborts, and the manifest gate discards the sample as a failed install — losing
the trace even though the payload ran. The sink answers HTTP/1.0 with
`Connection: close`: under keep-alive, Node's `http.get` never drains its event
loop and the hook hangs until the harness timeout, which cost 24 malware traces
before it was found.

---

## 2. Setup

```bash
cd ~/scbf2
python3 -m venv .venv
.venv/bin/pip install -U pip numpy scikit-learn torch joblib
```

Verify the shipped models load:

```bash
.venv/bin/python -c "
import joblib
b = joblib.load('models_pypi/multiwindow_gbm.joblib')
print('windows   ', b['windows'])
print('thresholds', {k: round(v,4) for k,v in b['thresholds'].items()})"
```

Expected: `windows [1500, 2200, 3000]`, thresholds `0.7997 / 0.9425 / 0.9568`.

---

## 3. Block a live install  ← the common case

```bash
sudo scbf-guard-pip install <package | path-to-archive>     # PyPI
sudo scbf-guard-npm install <package | path-to-tgz>         # npm
SCBF_DRY_RUN=1 sudo scbf-guard-pip install <x>              # decide, never kill
```

**Malware — expect BLOCKED:**

```bash
sudo scbf-guard-pip install data/raw/pypi_malware/eepl-4.5.2.tar.gz
```

```
[guard] multi-window stage loaded: windows [1500, 2200, 3000] ...
[guard] event 1500: p(malicious)=1.0000 distance=11.002 -> BLOCK
[guard] TERMINATING installer process tree (pid 11916) at event 1500
[+] VERDICT        : BLOCKED — install terminated mid-flight
[✗] BLOCKED — the installer was terminated before it finished.
```

**Clean — expect ALLOWED:**

```bash
sudo scbf-guard-pip install data/raw/pypi_benign/katna-0.9.2.tar.gz
```

**Verify a block was real:**

```bash
ls /tmp/scbf_install_env 2>/dev/null || echo "discarded — install did not persist"
```

### Reading the output

| field | meaning |
|---|---|
| **event N** | checkpoint at which the decision was taken |
| **p(malicious)** | model probability — drives the decision |
| **distance** | envelope distance, corroborating only; `0.000` for npm |
| **verdict** | BLOCK kills the process tree; WARN logs and continues |

### Known operational issues

**Registry installs are falsely blocked.** `pip install requests` and
`pip install certifi` are killed. All benign training traces came from local
`.tar.gz` files, so a registry download's network activity resembles
exfiltration. Measured 10/10 clean local artifacts allowed, 4/6 registry. Use
local artifacts until benign traces are recollected from the registry.

**Verdicts are not fully deterministic.** Trace length varies between runs, so a
package may block at 1500 on one run and 2200 on another, occasionally not at
all. Re-run to confirm.

---

## 4. Rebuild the dataset and model

```bash
# 1. extract the benchmark archives
unzip rq1_pypi_benign.zip  -d data/raw/pypi_benign
unzip rq1_pypi_malware.zip -d data/raw/pypi_malware

# 2. capture BOTH classes in ONE interleaved run  (~6 h for 2,000 packages)
sudo python3 capture/collect_dataset.py \
    --benign data/raw/pypi_benign --malware data/raw/pypi_malware \
    --out data/pip_traces --python $(uv python find 3.11)

# npm: add --ecosystem npm and point at the npm archives

# 3. audit — this is a GATE, not a report
python3 -m scbf.audit.leakage --traces data/pip_traces

# 4. what is actually in the traces
python3 -m scbf.audit.signal_report --traces data/pip_traces

# 5. tabular baseline — the bar the TGN must clear
python3 -m scbf.training.baseline --traces data/pip_traces

# 6. train 3 seeds on ONE shared split  (~30 min each, parallel)
for s in 42 7 1337; do
  python3 -m scbf.training.train --traces data/pip_traces \
      --random-window --seed $s --split-seed 42 --out models_pypi/seed$s &
done; wait

# 7. fit the multi-window decision stage
python3 -m scbf.training.build_multiwindow --tgn models_pypi --out models_pypi
```

### Why `--split-seed` must stay fixed

`--seed` used to drive **both** model initialisation and the train/val/test
partition, so every ensemble member got a *different* split. Scoring the
ensemble on one member's test set then meant the other two had trained on
**145 of its 210 packages**. That inflated PyPI test F1 to a false 93.22%; the
clean figure is 92.73%.

Verify after training:

```bash
.venv/bin/python -c "
import json
S={s: json.load(open(f'models_pypi/{s}/split_info.json')) for s in ('seed42','seed7','seed1337')}
p=lambda d,k:{x['path'] for x in d[k]}
ref=p(S['seed42'],'test')
for s in ('seed7','seed1337'):
    print(s, 'leaked:', len(ref & (p(S[s],'train')|p(S[s],'val'))))"
```

Both must print `leaked: 0`.

### Why `--random-window` is not optional

A fixed-prefix model is out-of-distribution at every other window. Trained only
at 3000 events, it scored known malware at **p=0.0001** when the live install
produced 1,900 events. Random-window training truncates each trace to a random
prefix (1200–4000) every epoch.

### Why step 3 is not optional

The audit failed the first dataset: a `/dev/pts` artifact appeared in 97.2% of
benign traces and 0% of malicious ones, purely from how they were collected. A
one-line rule on it scored **96.48% F1** — higher than the model. Any metric
computed on an unaudited dataset is meaningless.

### Interrupted capture

`--restart` resumes from the manifest; packages already recorded `ok` in
`data/pip_traces/manifest.jsonl` are skipped.

---

## 5. Evaluate

```bash
# per-seed
python3 -m scbf.training.evaluate --traces data/pip_traces --models models_pypi/seed42

# the shipped ensemble
python3 -m scbf.detection.seed_ensemble \
    --models models_pypi/seed42 models_pypi/seed7 models_pypi/seed1337 --at 3000

# cross-validated (tighter error bars; ~5 h)
python3 -m scbf.detection.cv_ensemble --traces data/pip_traces --folds 5 --at 3000
```

Test splits hold 59 malicious (PyPI) and 57 (npm) samples, so F1 carries roughly
±4%. The +1.73 F1 margin over OSCAR is inside that band — cross-validation is
what tightens it.

---

## 6. Troubleshooting

| symptom | cause |
|---|---|
| everything ALLOWED at p=0.0000 | sinkhole pointing at `127.0.0.1`, or registries blackholed. Check `getent hosts pypi.org` |
| traces far shorter than expected | registry unreachable; dependencies not fetched |
| `no ensemble members found` | `SCBF_ENSEMBLE` paths wrong after a rename |
| npm guard crashes on `envelope.json` | expected — npm ships without one; the guard treats it as optional |
| malware ALLOWED that blocked before | trace-length variance; re-run |
| clean package BLOCKED | if installed from the registry, this is the known defect |
