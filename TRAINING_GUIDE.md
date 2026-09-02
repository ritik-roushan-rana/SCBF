# SCBF Training Guide - Train/Test Split

This guide explains how to train the SCBF model with proper train/validation/test splits.

## Overview

The new training pipeline (`train_with_split.py`) implements:

- **70/15/15 split**: 70% training, 15% validation, 15% test
- **Stratified splitting**: Maintains class balance across splits
- **Validation-based early stopping**: Stops training when validation loss stops improving
- **Reproducible splits**: Fixed random seed for consistent results
- **Comprehensive evaluation**: Detailed metrics on test set

## Quick Start (In Linux VM)

### Option 1: Using Makefile (Recommended)

```bash
# 1. Collect data
sudo make collect-data

# 2. Train with split
sudo make train-split

# 3. Evaluate on test set
sudo make evaluate

# 4. Test detection
sudo make scan PKG=requests
```

### Option 2: Manual Commands

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

# 5. Test detection
sudo python3 -m scbf.detection.cli --package requests
```

## Dataset Split Details

### Split Ratios

- **Training set (70%)**: Used to optimize model parameters
- **Validation set (15%)**: Used for early stopping and hyperparameter tuning
- **Test set (15%)**: Held out for final evaluation only

### Stratification

The split maintains class balance:
- If you have 60 clean + 90 malicious packages:
  - Train: 42 clean + 63 malicious = 105 total
  - Val: 9 clean + 13 malicious = 22 total  
  - Test: 9 clean + 14 malicious = 23 total

### Reproducibility

- Fixed random seed (42) ensures same splits every time
- Split information saved to `models/checkpoints/split_info.json`
- You can inspect which packages went into which split

## Training Process

### 1. Data Collection (~30 minutes)

```bash
sudo python3 scripts/collect_clean_data.py
sudo python3 scripts/collect_malicious_data.py
```

**Output:**
- `data/clean/*.jsonl` - Behavioral traces from 60+ legitimate packages
- `data/malicious/*.jsonl` - Behavioral traces from 99 malicious packages

### 2. Model Training (~10 minutes)

```bash
sudo python3 -m scbf.training.train_with_split
```

**What happens:**
1. Loads all data files
2. Creates stratified train/val/test splits
3. Trains TGN encoder with contrastive loss
4. Validates after each epoch
5. Stops early if validation loss doesn't improve for 5 epochs
6. Saves best model based on validation performance

**Output files:**
- `models/tgn_v2_best.pt` - Best model (lowest validation loss)
- `models/checkpoints/tgn_epoch*.pt` - Per-epoch checkpoints
- `models/checkpoints/split_info.json` - Split information

**Training output example:**
```
Dataset splits:
  Train: 105 samples (42 clean, 63 malicious)
  Val:   22 samples (9 clean, 13 malicious)
  Test:  23 samples (9 clean, 14 malicious)

Epoch 1/50
  Train Loss: 2.3456 (clean=42, mal=63)
  Val Loss:   2.1234 (clean=9, mal=13)
  ✓ New best model (val_loss=2.1234)

Epoch 2/50
  Train Loss: 1.8765 (clean=42, mal=63)
  Val Loss:   1.9876 (clean=9, mal=13)
  ✓ New best model (val_loss=1.9876)
...

Early stopping at epoch 15 - no improvement for 5 epochs

FINAL TEST RESULTS:
Test Loss: 1.7654
Test Samples: 23 (9 clean, 14 malicious)
Test Compactness: 0.8234
Test Malicious Distance: 3.4567
```

### 3. Build Envelope (~1 minute)

```bash
sudo python3 -m scbf.training.build_envelope
```

Creates behavioral baseline/threshold for anomaly detection.

**Output:**
- `models/envelope_v2.npy` - Detection threshold

### 4. Evaluation

```bash
sudo python3 -m scbf.training.evaluate
```

**What it shows:**
- Accuracy, Precision, Recall, F1 score
- Confusion matrix (TP, TN, FP, FN)
- ROC-AUC score
- Distance statistics for clean vs. malicious
- Separate metrics for train/val/test sets

**Evaluation output example:**
```
================================================================================
TEST SET RESULTS
================================================================================

Dataset:
  Total samples: 23
  Clean: 9
  Malicious: 14

Distance Statistics:
  Clean distances: mean=1.2345, std=0.3456, min=0.8901, max=1.9876
  Malicious distances: mean=3.4567, std=0.7890, min=2.1234, max=5.6789

Classification (threshold=2.0000):
  Accuracy:  0.9130
  Precision: 0.9286
  Recall:    0.9286
  F1 Score:  0.9286
  FPR:       0.1111

Confusion Matrix:
                  Predicted
                Clean  Malicious
  Actual Clean      8  1
  Actual Mal        1  13

ROC-AUC: 0.9524
```

## Configuration Options

You can modify these parameters in `train_with_split.py`:

```python
# Split ratios
TRAIN_RATIO = 0.7   # 70% for training
VAL_RATIO = 0.15    # 15% for validation
TEST_RATIO = 0.15   # 15% for test

# Training hyperparameters
SEED = 42           # Random seed for reproducibility
MARGIN = 0.8        # Contrastive loss margin
LEARNING_RATE = 1e-3
EPOCHS = 50         # Maximum epochs
PATIENCE = 5        # Early stopping patience
NUM_NODES = 50000   # TGN node capacity
```

## Understanding the Metrics

### Accuracy
Percentage of correct predictions (clean and malicious).

### Precision
Of all packages predicted as malicious, what percentage were actually malicious?
- High precision = low false alarm rate

### Recall (True Positive Rate)
Of all actually malicious packages, what percentage did we detect?
- High recall = catch more malicious packages

### F1 Score
Harmonic mean of precision and recall.
- Good overall balance metric

### False Positive Rate (FPR)
Of all clean packages, what percentage did we incorrectly flag as malicious?
- Lower is better - avoid flagging legitimate packages

### ROC-AUC
Area under the ROC curve (0.5 = random, 1.0 = perfect).
- Measures overall discriminative ability

## Inspecting the Split

To see which packages went into which split:

```bash
cat models/checkpoints/split_info.json
```

Example:
```json
{
  "train": [
    {"path": "data/clean/requests.jsonl", "label": 0},
    {"path": "data/malicious/datadog__2023-01-08-reqsystem.jsonl", "label": 1},
    ...
  ],
  "val": [...],
  "test": [...],
  "train_size": 105,
  "val_size": 22,
  "test_size": 23,
  "timestamp": "2026-09-03T10:30:45.123456"
}
```

## Comparing Old vs. New Training

### Old Approach (`train.py`)
- No train/test split
- All data used for training
- No validation set
- Risk of overfitting
- Can't measure generalization

### New Approach (`train_with_split.py`)
- ✅ Proper train/val/test split
- ✅ Validation-based early stopping
- ✅ Test set for unbiased evaluation
- ✅ Reproducible splits
- ✅ Detailed metrics

## Troubleshooting

### "No data found"
```bash
# Collect data first
sudo python3 scripts/collect_clean_data.py
sudo python3 scripts/collect_malicious_data.py
```

### "Model not found"
```bash
# Train the model first
sudo python3 -m scbf.training.train_with_split
```

### "Split info not found"
```bash
# Run train_with_split.py, not the old train.py
sudo python3 -m scbf.training.train_with_split
```

### Low accuracy on test set
- Normal for first run with limited data
- Collect more training data
- Adjust MARGIN or LEARNING_RATE
- Try different SEED values to check stability

### Overfitting (train accuracy >> test accuracy)
- Increase PATIENCE for earlier stopping
- Collect more diverse training data
- Add regularization (future work)

## File Structure

```
scbf/
├── scbf/training/
│   ├── train.py              # Original training (no split)
│   ├── train_with_split.py   # NEW: Training with split ✨
│   ├── evaluate.py           # NEW: Test set evaluation ✨
│   └── build_envelope.py     # Envelope construction
├── models/
│   ├── tgn_v2_best.pt        # Best trained model
│   └── checkpoints/
│       ├── split_info.json   # Split information
│       ├── tgn_epoch*.pt     # Per-epoch checkpoints
│       └── evaluation_results.json  # Test metrics
├── data/
│   ├── clean/*.jsonl         # Clean package traces
│   └── malicious/*.jsonl     # Malicious package traces
└── Makefile                  # Convenient commands
```

## Next Steps After Training

1. **Review test metrics** - Check if performance is acceptable
2. **Scan packages** - Test on real packages:
   ```bash
   sudo make scan PKG=requests
   sudo make scan PKG=numpy
   ```
3. **Collect more data** - Improve model with more diverse samples
4. **Tune hyperparameters** - Adjust MARGIN, LEARNING_RATE, etc.
5. **Deploy** - Integrate into CI/CD pipeline

## Research Tips

### Experimenting with Different Splits

Edit `train_with_split.py`:
```python
# Try 80/10/10 split
TRAIN_RATIO = 0.8
VAL_RATIO = 0.1
TEST_RATIO = 0.1
```

### Multiple Random Seeds

Test model stability:
```bash
# Modify SEED in train_with_split.py and run multiple times
sed -i 's/SEED = 42/SEED = 123/' scbf/training/train_with_split.py
sudo python3 -m scbf.training.train_with_split
sudo python3 -m scbf.training.evaluate
```

### Cross-Validation (Future Work)

For small datasets, consider implementing k-fold cross-validation:
- Split data into k folds
- Train k times, each time using different fold as test
- Average results across all folds

## Citation

If you use this training pipeline in your research, please cite:

```
Supply Chain Behavioral Fingerprinting (SCBF)
Patent disclosure: "Supply Chain Package Behavioral Fingerprinting — TGN Revision"
Innovation 6 of 7
```

## Questions?

Check:
1. [README.md](README.md) - Project overview
2. [QUICKSTART.md](QUICKSTART.md) - Getting started guide
3. [docs/architecture.md](docs/architecture.md) - Technical details
4. This file - Training details

---

**Remember:** Always run with `sudo` in your Linux VM! eBPF requires root privileges.
