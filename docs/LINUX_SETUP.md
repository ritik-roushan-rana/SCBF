 # Ubuntu VM Setup for Full SCBF Pipeline

For **offline analysis** (training, envelope, `scan-trace`, `scan-batch`) any
platform with Python 3.9+ works, including macOS.

For **live capture** (`make scan PKG=...`, and `scripts/collect_zenodo.py`) you
need Linux with eBPF. This guide covers a fresh Ubuntu 22.04 / 24.04 VM.

## 1. System Requirements

- Ubuntu 22.04 or 24.04 (server or desktop)
- Kernel 5.15+ with eBPF enabled (default on modern Ubuntu)
- Root / sudo access
- ≥ 4 GB RAM, ≥ 20 GB disk

Check kernel:

```bash
uname -r          # should be 5.15+
```

## 2. Install System Dependencies

BCC (BPF Compiler Collection) is a **system package**, not a pip package. Install
it via apt:

```bash
sudo apt update

sudo apt install -y \
  python3-bpfcc \
  bpfcc-tools \
  linux-headers-$(uname -r) \
  build-essential \
  python3-pip \
  python3-venv \
  git
```

Verify BCC works:

```bash
sudo python3 -c "from bcc import BPF; print('BCC OK')"
```

If that fails, re-check the kernel headers match your running kernel.

## 3. Clone the Repository

```bash
git clone https://github.com/ritik-roushan-rana/SCBF.git
cd SCBF
```

## 4. Set Up the Python Environment

```bash
make install
```

This creates `.venv/` and installs the Python side of the requirements.

⚠️ **BCC bindings are NOT installed inside `.venv`** — they live in the system
`python3` interpreter, because that is where apt puts them. `monitor.sh`
launches its own Python subprocess as root, so this is fine: the model /
analysis side uses `.venv`, but the eBPF loader in `monitor.sh` uses the
system python where `bcc` is available.

## 5. Get the Trained Model

The `models/` directory is gitignored. You have two options:

### Option A — Copy the model from another machine (recommended)

If you have already trained on your workstation, just move the artifacts across:

```bash
# From the machine that has the trained model, e.g. macOS:
scp models/scbf_hybrid_v2.pt        <user>@<vm>:~/SCBF/models/
scp models/envelope_v2*.npy         <user>@<vm>:~/SCBF/models/
scp models/envelope_v2*.json        <user>@<vm>:~/SCBF/models/
scp models/checkpoints/split_info.json <user>@<vm>:~/SCBF/models/checkpoints/
```

That's it — the scanner reads these files directly and does not care where
they were produced.

### Option B — Retrain on the VM

Only needed if you don't have a trained model yet, or you want to retrain on
newly-collected data.

Place traces at `data/zenodo_13746167/{benign,malware}/traces/*.jsonl`
(download the Zenodo record `13746167`, or run the collector — see below),
then:

```bash
make validate-data
make train              # ~30-60 min on CPU
make build-envelope
```

### Optional — Collect fresh traces yourself

⚠️ **Warning:** the collector calls `pip install` on each package under
eBPF. Malicious packages will execute their install scripts inside the VM.
Only run this on a **disposable VM** with no credentials mounted and take a
snapshot beforehand.

```bash
sudo -E python3 scripts/collect_zenodo.py
```

## 6. Live Scan a Package

```bash
sudo -E make scan PKG=requests
```

That single command runs the entire live pipeline on Ubuntu:

```
   monitor.sh (eBPF)  →  captures syscalls during `pip install requests`
        ↓
   ITBG Constructor    →  streams events into a temporal graph
        ↓
   TGN Encoder         →  emits the 128-dim behavioral DNA vector
        ↓
   Envelope compare    →  distance to clean centroid vs threshold
        ↓
   Verdict engine      →  ALLOW / WARN / BLOCK  +  threat score 0-100
```

The `-E` flag preserves your user in `SUDO_USER` so `monitor.sh` can drop pip
back to your account (instead of installing the package into a root-owned venv).

Optional overrides:

```bash
# Install a specific artifact (a tarball path or PyPI spec)
sudo -E make scan PKG=some-suspicious \
  ARTIFACT=/tmp/some-suspicious-1.2.3.tar.gz \
  PYTHON=/home/$USER/.pyenv/versions/3.12.10/bin/python
```

## 7. Common Problems

**`bcc` import error inside `.venv`**  
BCC is a system package. `monitor.sh` uses the system `python3`, not
`.venv/bin/python`. This is by design — do not try to `pip install bcc`.

**Permission denied on `monitor.sh`**  
```bash
chmod +x monitor.sh
```

**Package installs as root**  
You launched `sudo make scan` without `-E`, so `SUDO_USER` was stripped. Use
`sudo -E make scan ...` or export `SCBF_USER=<your-user>` before running.

**`No such file or directory: /home/ubuntu/...`**  
`scripts/collect_zenodo.py` was originally written for a `/home/ubuntu` layout.
Edit the `ZENODO_DIR`, `PYTHON312`, and `--root` default at the top of that
file to match your username / paths, or pass overrides on the command line.

**`monitor.sh` prints "Failed to load eBPF"**  
Almost always missing kernel headers. Reinstall:

```bash
sudo apt install --reinstall linux-headers-$(uname -r)
```

## Safety Note

This tool is designed to detect malware. If you use the live-capture path
against untrusted packages, the malicious install scripts **will run in the
VM** during capture. Do not run collection on a machine with:

- SSH keys / cloud credentials
- Real user data
- Network access to anything sensitive

Use a throwaway VM and revert to a snapshot after each collection run.
