# SCBF Training Commands - Quick Reference

## ⚠️ Important: Run in Linux VM with sudo

All commands require:
- Linux kernel with eBPF support
- Root privileges (`sudo`)
- BCC installed
- Python 3.11+

## Quick Start (Recommended)

```bash
# 1. Collect data (~30 min)
sudo make collect-data

# 2. Train with train/val/test split (~10 min)
sudo make train-split

# 3. Evaluate on test set
sudo make evaluate

# 4. Test on a package
sudo make scan PKG=requests
```

## Alternative: Manual Commands

```bash
# 1. Collect data
sudo python3 scripts/collect_clean_data.py
sudo python3 scripts/collect_malicious_data.py

# 2. Train with split
sudo python3 -m scbf.training.train_with_split

# 3. Build envelope
sudo python3 -m scbf.training.build_envelope

# 4. Evaluate
sudo python3 -m scbf.training.evaluate

# 5. Scan package
sudo python3 -m scbf.detection.cli --package requests
```

## Training Options

### New Approach (with split) ⭐ RECOMMENDED
```bash
sudo make train-split
```
- Proper train/val/test split (70/15/15)
- Early stopping on validation
- Comprehensive evaluation metrics
- Reproducible results

### Old Approach (no split)
```bash
sudo make train
```
- Uses all data for training
- No validation or test set
- Risk of overfitting

## What Gets Created

### After Data Collection
```
data/
├── clean/
│   ├── requests.jsonl     # ~2000 events
│   ├── numpy.jsonl
│   └── ... (60+ packages)
└── malicious/
    ├── datadog__*.jsonl   # ~2000 events each
    └── ... (99 packages)
```

### After Training
```
models/
├── tgn_v2_best.pt             # Best trained model
├── envelope_v2.npy            # Detection threshold
└── checkpoints/
    ├── split_info.json        # Which data in which split
    ├── tgn_epoch*.pt          # Training checkpoints
    └── evaluation_results.json # Test metrics
```

## Viewing Results

### Check Split Information
```bash
cat models/checkpoints/split_info.json
```

### Check Evaluation Results
```bash
cat models/checkpoints/evaluation_results.json
```

### View Training Logs
Training progress is printed to terminal during training.

## Common Issues

### "python: command not found"
```bash
# Use python3 instead
sudo python3 -m scbf.training.train_with_split
```

### "Permission denied"
```bash
# Always use sudo
sudo python3 ...
```

### "Cannot import bcc"
```bash
# Install BCC
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc
```

### "No data found"
```bash
# Collect data first
sudo make collect-data
```

### "Model not found"
```bash
# Train first
sudo make train-split
```

## Makefile Commands Summary

```bash
make help           # Show all commands
make install        # Install package in dev mode
make collect-data   # Collect training data
make train          # Train (old way, no split)
make train-split    # Train (new way, with split) ⭐
make evaluate       # Evaluate on test set ⭐
make scan PKG=X     # Scan a package
make test           # Run test suite
make clean          # Remove temp files
```

## Configuration Files

### Training Config
Edit `scbf/training/train_with_split.py`:
```python
TRAIN_RATIO = 0.7    # 70% training
VAL_RATIO = 0.15     # 15% validation  
TEST_RATIO = 0.15    # 15% test
SEED = 42            # Random seed
MARGIN = 0.8         # Contrastive margin
LEARNING_RATE = 1e-3
EPOCHS = 50
PATIENCE = 5
```

### Package List
Edit `scripts/collect_clean_data.py`:
```python
PACKAGES = [
    "requests",
    "numpy",
    "flask",
    # Add more...
]
```

## Expected Timeline

| Step | Time | Output |
|------|------|--------|
| Data collection | ~30 min | 150+ .jsonl files |
| Training | ~10 min | Model checkpoints |
| Envelope | ~1 min | Detection threshold |
| Evaluation | ~2 min | Test metrics |
| Single scan | ~30 sec | Verdict |

## Typical Workflow

### First Time Setup
```bash
# 1. Collect data (once)
sudo make collect-data

# 2. Train model
sudo make train-split

# 3. Check results
sudo make evaluate
```

### Iterating
```bash
# Try different configs, then:
sudo make train-split
sudo make evaluate

# Compare results in:
models/checkpoints/evaluation_results.json
```

### Using the Model
```bash
# Scan packages
sudo make scan PKG=requests
sudo make scan PKG=suspicious-package
```

## Evaluation Metrics Explained

```
Accuracy  = (TP + TN) / Total      # Overall correctness
Precision = TP / (TP + FP)         # When we say "malicious", how often right?
Recall    = TP / (TP + FN)         # Of all malicious, how many caught?
F1        = 2 * P * R / (P + R)    # Balance of precision and recall
FPR       = FP / (FP + TN)         # False alarm rate
ROC-AUC   = Area under ROC curve   # Overall discrimination (0.5-1.0)
```

Where:
- TP = True Positives (correctly detected malicious)
- TN = True Negatives (correctly passed clean)
- FP = False Positives (clean flagged as malicious)
- FN = False Negatives (malicious passed as clean)

## Documentation

- **This file**: Quick command reference
- [TRAINING_GUIDE.md](TRAINING_GUIDE.md): Detailed training guide
- [TRAIN_TEST_SPLIT_SUMMARY.md](TRAIN_TEST_SPLIT_SUMMARY.md): What changed
- [README.md](README.md): Project overview
- [QUICKSTART.md](QUICKSTART.md): Getting started

## Pro Tips

1. **Always use `sudo`** - eBPF requires root
2. **Use `make` commands** - Easier than typing full paths
3. **Check logs carefully** - Spot data collection issues early
4. **Save evaluation results** - Compare different experiments
5. **Version your models** - Copy to dated folders before retraining

## Example Session

```bash
# SSH into Linux VM
ssh user@vm

# Navigate to project
cd /path/to/scbf

# Collect data (first time only)
sudo make collect-data
# Wait ~30 minutes...

# Train model
sudo make train-split
# Wait ~10 minutes...

# Check results
sudo make evaluate
# Review metrics

# Test detection
sudo make scan PKG=requests
# Should show "PASS" or "BLOCK"

# Try suspicious package
sudo make scan PKG=unknown-package
```

---

**Ready to train? Start with:** `sudo make train-split`
