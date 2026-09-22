# Re-capturing the NPM dataset with rich telemetry (Ubuntu VM)

Goal: re-trace every tarball in `rq1_npm_benign/` and `rq1_npm_malware/npm_malware/`
so each trace also carries **exec argv**, **connect destination (IP/port)** and an
**install → require() phase** tag. These are the fields the detector is missing
today (see `docs/NPM_RICH_TELEMETRY.md`).

> Run this in a **disposable VM with a snapshot**. The malware payloads execute
> for real, and the require() step imports each package. Take a snapshot before
> you start and roll back when done. Do not put real credentials, SSH keys or
> npm tokens on the VM.

## 1. VM setup (once)

Ubuntu 22.04 or 24.04, kernel ≥ 5.8, ≥ 2 vCPU, ≥ 20 GB disk, internet access
(the payloads and `npm install` both need it).

```bash
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) nodejs npm git build-essential python3
node -v && npm -v                       # any Node 18/20/22 is fine
sudo python3 -c "from bcc import BPF; print('bcc ok')"
```

Get the repo onto the VM (git clone, or copy just `scripts/npm_capture_rich.py`
and `scripts/npm_collect_rich.sh`) and make the scripts executable:

```bash
cd ~/SCBF
chmod +x scripts/npm_collect_rich.sh scripts/npm_capture_rich.py
```

Put the tarballs where they were before (any location works):

```
~/rq1_npm_benign/*.tgz
~/rq1_npm_malware/npm_malware/*.tgz
```

## 2. Smoke test on one package (2 min)

```bash
sudo -E python3 scripts/npm_capture_rich.py ~/rq1_npm_benign/$(ls ~/rq1_npm_benign | head -1) /tmp/test.jsonl
```

Expected tail of the output:

```
[+] phase=install done rc=0  events so far=1432
[+] phase=require done rc=0  events so far=1610
[+] {"package": "...", "install_rc": 0, ..., "n_exec": 3, "n_connect": 17, "n_require_phase": 178, ...}
```

Check that the new fields are present:

```bash
grep -m1 '"argv"'  /tmp/test.jsonl
grep -m1 '"daddr"' /tmp/test.jsonl
grep -c '"phase": "require"' /tmp/test.jsonl
```

If `bcc` fails to compile the program, the usual causes are missing kernel
headers (`linux-headers-$(uname -r)`) or a very old kernel (< 5.5 lacks
`bpf_probe_read_user`).

`sudo -E` matters: it preserves `SUDO_USER`, so npm/node run as your normal
user while the tracer runs as root (same as the original collector).

## 3. Full collection (~2–4 h for 1956 packages)

```bash
sudo -E ./scripts/npm_collect_rich.sh ~/rq1_npm_benign             ~/rq1_npm_rich/benign/traces
sudo -E ./scripts/npm_collect_rich.sh ~/rq1_npm_malware/npm_malware ~/rq1_npm_rich/malware/traces
```

* Safe to interrupt and re-run — finished tarballs are skipped.
* Per-package timeouts: 180 s install, 30 s require (override with
  `--install-timeout N --require-timeout N` after `OUT_DIR`).
* A one-line JSON summary per package goes to `~/rq1_npm_rich/<class>/collection_summary.jsonl`.
* Between packages the script kills leftovers and wipes `/tmp/scbf-npm-*`.
  A payload that installs a cron job or a systemd unit survives that, which is
  why the VM snapshot matters — roll back at the end (or halfway through if
  the machine starts behaving oddly).

## 4. Ship the traces back

```bash
cd ~ && tar czf rq1_npm_rich.tgz rq1_npm_rich/
ls -lh rq1_npm_rich.tgz
```

Copy `rq1_npm_rich.tgz` off the VM (scp / shared folder / cloud drive) and
extract it into the repo on the training machine as:

```
SCBF/data/rq1_npm_rich/benign/traces/*.jsonl
SCBF/data/rq1_npm_rich/malware/traces/*.jsonl
```

Then send me the path — or run the training yourself:

## 5. Train on the rich traces

```bash
python -m scbf.training.find_inert_npm data/rq1_npm_rich                       # optional
python -m scbf.training.train_npm_hybrid --data-dir data/rq1_npm_rich --rich --exclude-inert
python -m scbf.training.evaluate_npm models/scbf_npm_hybrid_v1.pt
```

`--rich` enables the 87 extra features; the checkpoint remembers the feature
set, so evaluation and the CLI need no flags. With the require() phase
captured, the "install-inert" list should shrink a lot — most of those
packages fire on import — and `--exclude-inert` may no longer be needed.
