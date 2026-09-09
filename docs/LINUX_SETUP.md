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

## 6. Live Scan (eBPF)

Installs any package under eBPF monitoring. The TGN classifier decides
based on the package's runtime behavior — no per-host calibration needed:

```bash
sudo -E make scan PKG=flask       # expect: ALLOW
sudo -E make scan PKG=six         # expect: ALLOW
sudo -E make scan PKG=requests    # expect: ALLOW
```
