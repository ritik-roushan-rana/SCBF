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
eBPF Capture → Event Normalization → ITBG Construction → TGN Encoding → Envelope Comparison → Verdict
```

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

### 1. Scan a package
```bash
sudo python -m scbf.detection.cli --package requests
```

### 2. Collect training data
```bash
sudo python scripts/collect_clean_data.py
sudo python scripts/collect_malicious_data.py
```

### 3. Train the model
```bash
sudo python -m scbf.training.train
```

### 4. Build behavioral envelope
```bash
sudo python -m scbf.training.build_envelope
```

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

**Phase 1 (Complete):**
- ✅ eBPF capture pipeline
- ✅ TGN encoder implementation
- ✅ Behavioral envelope construction
- ✅ CLI detector with calibrated thresholds

**Phase 2 (In Progress):**
- 🔄 Malicious dataset integration (Datadog)
- 🔄 Contrastive loss training (clean vs. malicious)
- ⏳ Stage-aware envelope profiling
- ⏳ CI/CD integration (GitHub Actions)
- ⏳ Mid-install kill-switch

## Known Limitations

- Linux-only (eBPF dependency)
- Residual correlation (0.79) between event count and distance score
- Small clean dataset (21-60 packages) — Phase 2 scaling in progress

## Training Data

- **Clean packages**: 60+ top PyPI packages
- **Malicious samples**: 99 confirmed malicious packages (Datadog dataset)
- **Event streams**: ~2000+ events/package average

## Performance

- Capture overhead: ~5-10% CPU during install
- Inference latency: <100ms per verdict
- Training time: ~5-10 minutes (60 clean + 99 malicious samples)

## Citation

Based on patent disclosure: "Supply Chain Package Behavioral Fingerprinting — TGN Revision" (Innovation 6 of 7)

## License

[To be determined]
