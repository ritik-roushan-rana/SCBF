# SCBF Quick Start Guide

## Prerequisites

**System Requirements:**
- Linux (kernel 5.x+ with eBPF support)
- Python 3.11+
- Root/sudo access (for eBPF)
- ~2GB RAM for training
- ~500MB disk for data

**Check kernel support:**
```bash
uname -r  # Should be 5.x or higher
ls /sys/kernel/debug/tracing/  # Should exist
```

## Installation

### 1. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y \
    bpfcc-tools \
    linux-headers-$(uname -r) \
    python3-bpfcc \
    linux-tools-$(uname -r) \
    python3-pip \
    python3-dev
```

**Verify BCC:**
```bash
sudo python3 -c "from bcc import BPF; print('BCC OK')"
```

### 2. Install SCBF Package

```bash
cd scbf_structured
pip install -e .
```

Or manually:
```bash
pip install -r requirements.txt
```

## First Run - Complete Workflow

### Step 1: Collect Training Data (~30 minutes)

**Clean packages** (legitimate PyPI packages):
```bash
sudo python scripts/collect_clean_data.py
```

This captures install-time behavior for 60+ popular packages (requests, numpy, django, etc.)

**Expected output:**
```
Installing requests...
  captured 1614 events
Installing numpy...
  captured 4237 events
...
```

**Malicious packages** (Datadog dataset):
```bash
# First, get the Datadog malicious package dataset
cd ~
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/DataDog/malicious-software-packages-dataset.git
cd malicious-software-packages-dataset
git sparse-checkout set pypi

# Then run collection
cd /path/to/scbf_structured
sudo python scripts/collect_malicious_data.py
```

**Expected output:**
```
Found 1234 candidate samples, using up to 150
Processing datadog__ctx-0.1.2...
  captured 892 events
...
Done. Captured 99 malicious samples into data/malicious/
```

**Verify data:**
```bash
ls data/clean/ | wc -l    # Should show ~60
ls data/malicious/ | wc -l  # Should show ~99
head -5 data/clean/requests.jsonl
```

### Step 2: Train the Model (~5-10 minutes)

```bash
sudo python -m scbf.training.train
```

**Expected output:**
```
Clean sessions: 60, Malicious sessions: 99
epoch 0 loss 0.1859 (clean=60, mal=99)
epoch 1 loss 0.1405 (clean=60, mal=99)
...
  -> new best (loss=0.0169), saved to tgn_v2_best.pt
...
Early stopping at epoch 12 — no improvement for 5 epochs.
Training complete. Best loss: 0.0169
```

### Step 3: Build Behavioral Envelope

```bash
sudo python -m scbf.training.build_envelope
```

**Expected output:**
```
Envelope v2 built from 60 clean sessions
```

### Step 4: Verify Separation

```bash
sudo python scripts/check_distances.py
```

**Expected output:**
```
=== CLEAN packages ===
data/clean/requests.jsonl: 0.1034
data/clean/numpy.jsonl: 0.0876
...
Clean:     mean=0.0957, max=0.1774
Malicious: mean=0.2846, min=0.1893

Separation gap (mal_min - clean_max): 0.0119  ← Positive = good!
```

A positive gap means you have clean separation — threshold between clean_max and mal_min will correctly classify all samples.

### Step 5: Scan a Package

```bash
sudo python -m scbf.detection.cli --package requests
```

**Expected output:**
```
=== SCBF Scan Report: requests ===
Events captured : 1614
Envelope distance: 0.1034
Verdict         : ALLOW
```

**Try a suspicious package** (if you have one from the malicious dataset):
```bash
# This would show BLOCK if genuinely malicious
sudo python -m scbf.detection.cli --package some-typosquat-pkg
```

## Using Makefile Shortcuts

```bash
# Collect all data
sudo make collect-data

# Train model + build envelope
sudo make train

# Scan a package
sudo make scan PKG=requests

# Clean up temp files
make clean
```

## Troubleshooting

### Issue: "Permission denied" on BPF()

**Cause:** eBPF requires root  
**Fix:** Always run with `sudo`

### Issue: "Failed to load program: Invalid argument"

**Cause:** Kernel headers mismatch  
**Fix:**
```bash
uname -r
apt list --installed | grep linux-headers
# Ensure they match, reinstall if needed:
sudo apt install linux-headers-$(uname -r)
```

### Issue: "No events captured"

**Cause:** PID tracking lost, or install too fast  
**Fix:** Check the package actually installs (try manually first):
```bash
pip install --target=/tmp/test requests
```

### Issue: Training loss stays at 0.0

**Cause:** No data files found  
**Fix:** Verify paths in scripts match actual data location:
```bash
ls data/clean/*.jsonl | head
ls data/malicious/*.jsonl | head
```

### Issue: All clean packages get WARN/BLOCK

**Cause:** Thresholds not calibrated to your data  
**Fix:** Run `check_distances.py` and update thresholds in `scbf/detection/cli.py`:
```python
WARN_THRESHOLD = clean_max + small_margin
BLOCK_THRESHOLD = somewhere_between_clean_max_and_mal_min
```

## Next Steps

**For Development:**
- Read `docs/architecture.md` for system design
- Check `tests/` for unit tests
- Add more clean packages to training set

**For Production Use:**
- Expand training data to 1K+ clean, 500+ malicious
- Integrate into CI/CD (GitHub Actions, pre-commit hooks)
- Implement mid-install kill-switch
- Add explainability (report triggering event)

**For Research:**
- Test against novel malicious patterns
- Tune TGN architecture (memory dim, attention heads)
- Experiment with alternative envelope strategies
- Add network capture (tcp_connect events)

## Sample Output Files

After full workflow:
```
scbf_structured/
├── data/
│   ├── clean/
│   │   ├── requests.jsonl (1614 events)
│   │   ├── numpy.jsonl (4237 events)
│   │   └── ... (~60 files)
│   └── malicious/
│       ├── datadog__ctx-0.1.2.jsonl (892 events)
│       └── ... (~99 files)
├── models/
│   ├── tgn_v2_best.pt (trained model, ~15MB)
│   ├── tgn_v2_final.pt
│   ├── envelope_v2.npy (128-dim centroid, ~1KB)
│   └── checkpoints/
│       ├── tgn_epoch0.pt
│       ├── tgn_epoch1.pt
│       └── ...
└── last_capture.jsonl (most recent scan)
```

## Getting Help

- Architecture questions: `docs/architecture.md`
- API reference: check docstrings in `scbf/` modules
- Issues: [GitHub Issues] (if published)
- Original design: Patent disclosure document
