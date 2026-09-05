# Training Configuration ✅

**Status:** Ready to train on your 1,344-package dataset

## Training Settings

### Dataset Split
- **Train:** 70% (~940 packages)
- **Validation:** 15% (~202 packages)  
- **Test:** 15% (~202 packages)

Stratified split ensures balanced class distribution in each set.

### Training Parameters
```python
EPOCHS = 40           # Maximum training epochs
PATIENCE = 5          # Early stopping patience
LEARNING_RATE = 1e-3  # Adam optimizer learning rate
MARGIN = 0.8          # Contrastive loss margin
SEED = 42             # Reproducibility
```

### Early Stopping
- Monitors validation loss every epoch
- Stops if no improvement for 5 consecutive epochs
- Saves best model based on validation loss
- Loads best model for final test evaluation

### Loss Function
**Contrastive Loss:**
```
Loss = compactness(clean) + max(0, margin - distance(malicious, centroid))
```

**Components:**
1. **Compactness:** Keeps benign packages close together
2. **Separation:** Pushes malicious packages away from benign centroid
3. **Margin:** Minimum separation distance (0.8)

## Training Process

### What Happens

1. **Load Dataset**
   ```
   data/zenodo_13746167/benign/traces/*.jsonl  (959 files)
   data/zenodo_13746167/malware/traces/*.jsonl (385 files)
   Total: 1,344 packages
   ```

2. **Split Data**
   ```
   Shuffle with seed=42 (reproducible)
   Split into 70/15/15 (train/val/test)
   Balance classes in training batches
   ```

3. **Training Loop**
   ```
   For each epoch (max 40):
     1. Train on training set
     2. Evaluate on validation set
     3. Save checkpoint
     4. Check if best model (save if yes)
     5. Early stopping check
   ```

4. **Final Evaluation**
   ```
   Load best model (lowest val loss)
   Evaluate on test set
   Report final metrics
   ```

## Expected Output

### During Training
```
Loading data paths...
Found 959 benign packages
Found 385 malware packages

Splitting data (train=0.7, val=0.15, test=0.15)...

Dataset splits:
  Train: 940 samples (671 clean, 269 malicious)
  Val:   202 samples (144 clean, 58 malicious)
  Test:  202 samples (144 clean, 58 malicious)

Initializing model...

Starting training (max 40 epochs, patience=5)...
================================================================================

Epoch 1/40
  Train Loss: 2.3456 (clean=671, mal=269)
  Val Loss:   2.1234 (clean=144, mal=58)
  Val Compactness: 1.5678
  Val Mal Distance: 3.2109
  ✓ New best model (val_loss=2.1234)

Epoch 2/40
  Train Loss: 1.8765 (clean=671, mal=269)
  Val Loss:   1.9123 (clean=144, mal=58)
  Val Compactness: 1.3456
  Val Mal Distance: 3.4567
  ✓ New best model (val_loss=1.9123)

...

Epoch 15/40
  Train Loss: 0.5432 (clean=671, mal=269)
  Val Loss:   0.6543 (clean=144, mal=58)
  No improvement (1/5)

...

Early stopping at epoch 20 - no improvement for 5 epochs

================================================================================
Loading best model for test evaluation...

Evaluating on test set...

================================================================================
FINAL TEST RESULTS:
================================================================================
Test Loss: 0.6234
Test Samples: 202 (144 clean, 58 malicious)
Test Compactness: 0.4123
Test Malicious Distance: 4.5678
================================================================================

Training complete!
Best model saved to: models/tgn_v2_best.pt
Best validation loss: 0.6123
Test loss: 0.6234
Checkpoints saved in: models/checkpoints/
```

### Files Created

```
models/
├── tgn_v2_best.pt                # Best model (for deployment)
└── checkpoints/
    ├── split_info.json           # Reproducible split information
    ├── tgn_best.pt               # Best checkpoint with optimizer
    ├── tgn_epoch1.pt             # Epoch 1 checkpoint
    ├── tgn_epoch2.pt             # Epoch 2 checkpoint
    └── ...                       # All epoch checkpoints
```

## Running Training

### Quick Start
```bash
# Train with defaults (40 epochs, early stopping)
sudo make train-split
```

### Manual
```bash
# Activate environment if needed
# cd /path/to/SCBF

# Train (requires sudo for eBPF compatibility check)
sudo python3 -m scbf.training.train_with_split
```

### Monitor Progress
```bash
# Training will print progress every epoch
# Watch for:
# - Decreasing train/val loss (good)
# - Increasing mal distance (good)
# - Decreasing compactness (good)
# - Early stopping message (normal if convergence reached)
```

## Training Time Estimates

Based on dataset size (1,344 packages, ~5.9M events):

- **Per epoch:** ~2-5 minutes
- **40 epochs:** ~1.5-3 hours
- **With early stopping:** Usually 15-25 epochs → ~1-2 hours
- **On modern CPU:** Closer to lower end
- **On older CPU:** Closer to upper end

**Tip:** Use `screen` or `tmux` for long training:
```bash
screen -S scbf-training
sudo python3 -m scbf.training.train_with_split
# Ctrl+A, D to detach
# screen -r scbf-training to reattach
```

## Interpreting Results

### Good Training Signs
- ✅ Val loss decreases over epochs
- ✅ Train/val loss track together (no overfitting)
- ✅ Malicious distance increases (separation)
- ✅ Compactness decreases (tight benign cluster)

### Warning Signs
- ⚠️ Val loss increases while train loss decreases (overfitting)
- ⚠️ Very low compactness (<0.01) with high mal distance (collapse)
- ⚠️ No improvement after epoch 1 (learning rate too high/low)

### Early Stopping
```
Early stopping at epoch 20 - no improvement for 5 epochs
```
This is **GOOD** - means:
- Model converged
- Best performance reached
- Preventing overfitting
- Saved training time

## After Training

### Build Envelope
```bash
sudo python3 -m scbf.training.build_envelope

# Creates: models/envelope_v2.npy
# This is the benign centroid for detection
```

### Evaluate
```bash
python3 -m scbf.training.evaluate

# Reports test set metrics:
# - Accuracy
# - Precision/Recall
# - ROC-AUC
# - Distance distributions
```

### Scan Packages
```bash
sudo make scan PKG=requests

# Uses trained model + envelope for detection
# Output: ALLOW/WARN/BLOCK verdict
```

## Troubleshooting

### "No data found"
**Cause:** Trace files not in correct location

**Fix:**
```bash
# Check files exist
ls data/zenodo_13746167/benign/traces/*.jsonl | wc -l
ls data/zenodo_13746167/malware/traces/*.jsonl | wc -l

# Should show 959 and 385 respectively
```

### "CUDA out of memory"
**Cause:** GPU memory exhausted (unlikely on CPU)

**Fix:** Already using CPU-only mode, should not occur

### "Permission denied"
**Cause:** Need sudo for some operations

**Fix:**
```bash
sudo python3 -m scbf.training.train_with_split
```

### Very slow training
**Cause:** Large dataset, CPU-bound

**Solutions:**
- Use `screen`/`tmux` for background execution
- Train overnight
- Reduce `EPOCHS` to 20 for faster testing

## Configuration Changes

Edit `scbf/training/train_with_split.py` to adjust:

```python
# Line ~310
EPOCHS = 40           # Change max epochs
PATIENCE = 5          # Change early stopping patience
LEARNING_RATE = 1e-3  # Change learning rate
MARGIN = 0.8          # Change contrastive margin
```

## Next Steps After Training

1. **Evaluate model:**
   ```bash
   python3 -m scbf.training.evaluate
   ```

2. **Build envelope:**
   ```bash
   sudo python3 -m scbf.training.build_envelope
   ```

3. **Test detection:**
   ```bash
   sudo make scan PKG=requests
   ```

4. **Deploy:**
   - Use `models/tgn_v2_best.pt` and `models/envelope_v2.npy`
   - Integrate into CI/CD pipeline
   - Monitor real packages

## Summary

✅ **Train/Val/Test Split:** 70/15/15% (stratified)  
✅ **Max Epochs:** 40  
✅ **Early Stopping:** Patience=5 epochs  
✅ **Dataset:** 1,344 packages (959 benign, 385 malware)  
✅ **Expected Time:** 1-2 hours (with early stopping)  
✅ **Output:** Best model + all checkpoints + split info  

**Ready to train!**
```bash
sudo make train-split
```

---

**Documentation:**
- This file: Training configuration
- `docs/DATASET_READY.md`: Dataset status
- `docs/TRAINING_DATA_FORMAT.md`: Data requirements
- `docs/MONITOR_USAGE.md`: Data collection guide
