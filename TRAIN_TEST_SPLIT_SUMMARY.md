# Train-Test Split Implementation Summary

## What Was Added

This update adds proper train/validation/test splitting to the SCBF training pipeline.

## New Files Created

### 1. `scbf/training/train_with_split.py` ⭐
Complete rewrite of the training script with:
- **70/15/15 train/val/test split** (configurable)
- **Stratified splitting** - maintains class balance
- **Validation-based early stopping** - prevents overfitting
- **Reproducible splits** - fixed random seed
- **Per-epoch checkpointing** - save progress
- **Best model tracking** - based on validation loss
- **Detailed logging** - track all metrics

### 2. `scbf/training/evaluate.py` ⭐
Comprehensive evaluation script that computes:
- **Classification metrics**: Accuracy, Precision, Recall, F1, FPR
- **Confusion matrix**: TP, TN, FP, FN
- **Distance statistics**: Mean, std, min, max for clean vs. malicious
- **ROC-AUC score**: Overall discriminative ability
- **Separate reports** for train/val/test sets
- **JSON output** - save results for analysis

### 3. `TRAINING_GUIDE.md` 📖
Comprehensive documentation covering:
- Quick start commands
- Detailed explanation of each step
- Metric interpretation
- Troubleshooting guide
- Configuration options
- Research tips

### 4. `TRAIN_TEST_SPLIT_SUMMARY.md` (this file) 📋
Quick reference for what changed.

## Updated Files

### `Makefile`
Added new commands:
```bash
make train-split   # Train with proper splits
make evaluate      # Evaluate on test set
make help          # Updated help text
```

## Key Features

### 1. Proper Data Splitting
```python
train_set, val_set, test_set = split_data(
    clean_paths, mal_paths,
    train_ratio=0.7,
    val_ratio=0.15, 
    test_ratio=0.15,
    seed=42  # Reproducible
)
```

### 2. Class Balance Preservation
- Splits each class separately
- Maintains proportion in all splits
- Handles class imbalance

### 3. Early Stopping
- Monitors validation loss
- Stops if no improvement for 5 epochs
- Prevents overfitting
- Saves best model automatically

### 4. Comprehensive Evaluation
```python
metrics = {
    'accuracy': 0.9130,
    'precision': 0.9286,
    'recall': 0.9286,
    'f1': 0.9286,
    'fpr': 0.1111,
    'roc_auc': 0.9524,
    'confusion_matrix': [[8, 1], [1, 13]]
}
```

### 5. Reproducibility
- Fixed random seed
- Split info saved to JSON
- Track which packages in which split
- Checkpoint every epoch

## How to Use

### Quick Start (Linux VM)
```bash
# Collect data
sudo make collect-data

# Train with split
sudo make train-split

# Evaluate
sudo make evaluate

# Test detection
sudo make scan PKG=requests
```

### Manual Commands
```bash
# Train
sudo python3 -m scbf.training.train_with_split

# Evaluate
sudo python3 -m scbf.training.evaluate
```

## Output Files

### Training Outputs
```
models/
├── tgn_v2_best.pt                      # Best model (validation)
└── checkpoints/
    ├── tgn_epoch1.pt                   # Epoch checkpoints
    ├── tgn_epoch2.pt
    ├── ...
    ├── split_info.json                 # Split configuration
    └── evaluation_results.json         # Test metrics
```

### Split Info (`split_info.json`)
```json
{
  "train": [
    {"path": "data/clean/requests.jsonl", "label": 0},
    {"path": "data/malicious/...", "label": 1}
  ],
  "val": [...],
  "test": [...],
  "train_size": 105,
  "val_size": 22,
  "test_size": 23,
  "timestamp": "2026-09-03T..."
}
```

### Evaluation Results (`evaluation_results.json`)
```json
{
  "train": {
    "metrics": {
      "accuracy": 0.95,
      "precision": 0.94,
      "recall": 0.96,
      "f1": 0.95,
      "fpr": 0.05,
      ...
    },
    "n_samples": 105,
    "auc": 0.98
  },
  "val": {...},
  "test": {...}
}
```

## Comparison: Old vs. New

| Feature | Old (`train.py`) | New (`train_with_split.py`) |
|---------|------------------|----------------------------|
| Data split | ❌ No split | ✅ 70/15/15 |
| Validation | ❌ None | ✅ Validation set |
| Test set | ❌ None | ✅ Held-out test |
| Early stopping | ⚠️ Fixed epochs | ✅ Validation-based |
| Overfitting risk | ⚠️ High | ✅ Low |
| Metrics | ⚠️ Training loss only | ✅ Comprehensive |
| Reproducibility | ⚠️ Random | ✅ Fixed seed |
| Checkpoints | ⚠️ Final only | ✅ Every epoch |
| Split info | ❌ None | ✅ Saved to JSON |
| Evaluation | ❌ None | ✅ Full metrics |

## Benefits

### 1. Unbiased Evaluation
- Test set never seen during training
- True measure of generalization
- Catch overfitting early

### 2. Better Model Selection
- Validation set guides early stopping
- Best model based on unseen data
- Avoid training too long

### 3. Research Quality
- Reproducible results
- Standard ML practices
- Publication-ready metrics

### 4. Debugging
- Track train vs. val performance
- Identify overfitting
- Compare different hyperparameters

### 5. Transparency
- Know exactly which data was used where
- Audit model performance
- Reproduce experiments

## Configuration

Edit `scbf/training/train_with_split.py`:

```python
# Data split
TRAIN_RATIO = 0.7    # 70% training
VAL_RATIO = 0.15     # 15% validation
TEST_RATIO = 0.15    # 15% test

# Reproducibility
SEED = 42            # Random seed

# Training
MARGIN = 0.8         # Contrastive margin
LEARNING_RATE = 1e-3
EPOCHS = 50          # Maximum
PATIENCE = 5         # Early stopping

# Model
NUM_NODES = 50000    # TGN capacity
```

## Example Output

### Training
```
Dataset splits:
  Train: 105 samples (42 clean, 63 malicious)
  Val:   22 samples (9 clean, 13 malicious)
  Test:  23 samples (9 clean, 14 malicious)

Starting training (max 50 epochs, patience=5)...

Epoch 1/50
  Train Loss: 2.3456 (clean=42, mal=63)
  Val Loss:   2.1234 (clean=9, mal=13)
  Val Compactness: 0.8234
  Val Mal Distance: 2.4567
  ✓ New best model (val_loss=2.1234)

Epoch 2/50
  Train Loss: 1.8765 (clean=42, mal=63)
  Val Loss:   1.9876 (clean=9, mal=13)
  Val Compactness: 0.7123
  Val Mal Distance: 2.8901
  ✓ New best model (val_loss=1.9876)

...

Early stopping at epoch 15 - no improvement for 5 epochs

FINAL TEST RESULTS:
====================
Test Loss: 1.7654
Test Samples: 23 (9 clean, 14 malicious)
Test Compactness: 0.6789
Test Malicious Distance: 3.1234
```

### Evaluation
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

## Next Steps

1. **Collect data** in your Linux VM:
   ```bash
   sudo make collect-data
   ```

2. **Train with split**:
   ```bash
   sudo make train-split
   ```

3. **Evaluate**:
   ```bash
   sudo make evaluate
   ```

4. **Test detection**:
   ```bash
   sudo make scan PKG=requests
   ```

5. **Iterate**:
   - Collect more data
   - Tune hyperparameters
   - Try different split ratios
   - Compare different seeds

## Documentation

- **Detailed guide**: [TRAINING_GUIDE.md](TRAINING_GUIDE.md)
- **Project overview**: [README.md](README.md)
- **Quick start**: [QUICKSTART.md](QUICKSTART.md)
- **Architecture**: [docs/architecture.md](docs/architecture.md)

## Notes

- ⚠️ **Must run in Linux VM** - eBPF not available on macOS
- ⚠️ **Requires sudo** - eBPF needs root privileges
- ⚠️ **Use python3** not `python` on most systems
- ✅ **Backward compatible** - Old `train.py` still available

---

**Questions?** See [TRAINING_GUIDE.md](TRAINING_GUIDE.md) for detailed explanations.
