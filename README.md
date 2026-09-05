# Supply Chain Behavioral Fingerprinting (SCBF)

A real-time malicious package detection system using Temporal Graph Networks and eBPF-based behavioral monitoring.

## Overview

SCBF intercepts package installation at the kernel level (via eBPF), captures syscall-level behavioral patterns, and uses a Temporal Graph Network to detect supply chain attacks during installation — before malicious code can execute.

## Key Features

- **Real-time detection**: Streaming verdict during package installation
- **Behavioral fingerprinting**: TGN-based "DNA" encoding of install behavior
- **Kernel-level capture**: eBPF tracing (Linux) for tamper-resistant monitoring
- **Mid-install kill-switch**: Process termination on BLOCK verdict
- **Explainability**: Reports specific events triggering anomalies

## Architecture

```
eBPF Capture (monitor.sh) → Event Normalization → ITBG Construction → TGN Encoding → Envelope Comparison → Verdict
```

**New Monitoring System:**
- `monitor.sh` - Improved eBPF monitor with better process tracking
- `scripts/collect_zenodo.py` - Automated data collection
- Individual trace files for each package

## Installation

### Prerequisites
- Linux kernel 5.x+ with eBPF support
- Python 3.11+
- BCC (BPF Compiler Collection)

```bash
# Install system dependencies
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc

# Install Python dependencies
pip install -r requirements.txt
```

## Quick Start

### Adding Your Dataset

```bash
# 1. Create structure
make prepare-structure

# 2. Place your dataset files
cp /path/to/malware.jsonl data/zenodo_13746167/malware/data/
cp /path/to/benign.jsonl data/zenodo_13746167/benign/data/

# 3. Validate
make validate-data

# 4. Train
sudo make train-split

# 5. Scan packages
sudo make scan PKG=requests
```

See [SIMPLE_SETUP.md](docs/restructuring/SIMPLE_SETUP.md) for detailed instructions.

### Alternative: Collect Your Own Data (Advanced)

If you want to collect behavioral traces yourself:

```bash
# Requires: Linux with eBPF/BCC, root access
sudo make collect-data
make aggregate-data
make validate-data
sudo make train-split
```

### Documentation
- [Architecture](docs/architecture.md) - System architecture deep-dive
- [Dataset Guide](docs/restructuring/SIMPLE_SETUP.md) - How to add your dataset
- [Data Format](data/README.md) - Event format and structure

## Project Structure

```
scbf/
├── scbf/               # Core package
│   ├── capture/        # eBPF event capture
│   ├── models/         # TGN encoder & graph construction
│   ├── training/       # Training and envelope building
│   └── detection/      # CLI and verdict engine
├── scripts/            # Data collection utilities
├── tests/              # Unit and integration tests
├── data/               # Training/validation data
└── models/             # Saved model weights
```

## Current Status

**Ready for dataset placement:**
- ✅ eBPF capture pipeline
- ✅ TGN encoder implementation
- ✅ Behavioral envelope construction
- ✅ CLI detector with calibrated thresholds
- ✅ Clean directory structure for final dataset

**Place your dataset:**
- See [docs/restructuring/SIMPLE_SETUP.md](docs/restructuring/SIMPLE_SETUP.md)
- Required: `malware.jsonl` and `benign.jsonl`
- Location: `data/zenodo_13746167/`

## Known Limitations

- Linux-only (eBPF dependency)
- Requires root privileges for monitoring
- Dataset provided separately (see [docs/restructuring/SIMPLE_SETUP.md](docs/restructuring/SIMPLE_SETUP.md))

## Training Data

The SCBF dataset uses behavioral traces (JSONL event logs) from:
- **Malware samples**: Confirmed malicious packages
- **Benign packages**: Top PyPI packages

**Dataset format:**
- Event-level JSONL (one event per line)
- Event types: `exec`, `open`, `connect`
- ~2000-3000 events per package on average

**To add your dataset:**
```bash
make prepare-structure
# Place malware.jsonl and benign.jsonl in data/zenodo_13746167/
make validate-data
sudo make train-split
```

See [data/README.md](data/README.md) for detailed format specifications.

## Performance

- Capture overhead: ~5-10% CPU during install
- Inference latency: <100ms per verdict
- Training time: ~5-10 minutes (60 clean + 99 malicious samples)

## Citation

Based on patent disclosure: "Supply Chain Package Behavioral Fingerprinting — TGN Revision" (Innovation 6 of 7)

## License

[To be determined]
