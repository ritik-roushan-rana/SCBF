# Linux Setup — Install, Run, Scan

Minimal steps to get SCBF running on Ubuntu and scan both a **benign** and a
**malicious** package trace.

## 1. Install

```bash
# System dependencies (BCC / eBPF)
sudo apt update
sudo apt install -y \
  python3-bpfcc bpfcc-tools linux-headers-$(uname -r) \
  build-essential python3-pip python3-venv git

# Clone and set up Python env
git clone https://github.com/ritik-roushan-rana/SCBF.git
cd SCBF
make install
source .venv/bin/activate
```

Place the trained model files in `models/` (copy from another machine):

```
models/scbf_hybrid_v2.pt
models/envelope_v2*.npy
models/envelope_v2*.json
models/checkpoints/split_info.json
```

## 2. Verify

```bash
make validate-data
make help
```

## 3. Scan a Benign Package

```bash
make scan-trace TRACE=data/zenodo_13746167/benign/traces/AerospikeClientMock-1.0.3.1.tar.gz.jsonl
```

Expected verdict: **ALLOW** (low threat score).

## 4. Scan a Malicious Package

```bash
make scan-trace TRACE=data/zenodo_13746167/malware/traces/BeautifulSoop-1.0.0.tar.gz.jsonl
```

Expected verdict: **BLOCK** (high threat score).

## 5. Batch Scan (Both Classes)

```bash
# All malware traces
make scan-batch DIR=data/zenodo_13746167/malware/traces/

# All benign traces
make scan-batch DIR=data/zenodo_13746167/benign/traces/
```

## 6. Calibrate the Envelope for This Host (one time)

The envelope shipped with the model was built on the Zenodo dataset's capture
environment. Live installs on your VM produce systematically different syscall
traces (different pip version, Python version, cache state, paths). Without
calibration, live `make scan PKG=...` will falsely BLOCK even clean packages.

Fix it once, then live scans work correctly:

```bash
make recalibrate
```

That runs two steps:

1. `capture-live-benign` — installs ~30 known-clean packages (six, click,
   flask, requests, pytest, …) under eBPF and stores their traces in
   `data/traces/live_benign/`.
2. `build-envelope` — rebuilds the envelope from the combined
   Zenodo + local clean traces.

Takes ~5–10 minutes total. Only needs to be done once per host.

## 7. Live Scan (eBPF)

Installs a package under eBPF monitoring and emits a verdict in real time:

```bash
sudo -E make scan PKG=flask       # expect: ALLOW
sudo -E make scan PKG=six         # expect: ALLOW
sudo -E make scan PKG=requests    # expect: ALLOW
```

If clean packages still show BLOCK, run `make recalibrate` first.
