# Accuracy Improvement Plan

## Current Problem

**Test Accuracy: 71.78%** but with **very poor recall (8.62%)**

### Root Cause:
The model isn't separating malicious packages from benign ones:

```
Distance Statistics:
- Clean packages:     0.65 ± 0.15 (range: 0.31 - 0.99)
- Malicious packages: 0.74 ± 0.16 (range: 0.41 - 1.03)
- Separation:         Only 0.09 difference in means
- Overlap:            HUGE - many malicious closer than clean!
```

**Current metrics:**
```
Accuracy:  71.78%
Precision: 55.56%
Recall:     8.62%  ← Only catching 8.6% of malware!
F1 Score:  14.93%
ROC-AUC:   0.6460
```

**Confusion Matrix:**
```
                Predicted
              Clean  Malicious
Actual Clean    140      4      ← Good: 97% correct
Actual Mal       53      5      ← BAD: Only 9% caught!
```

## Why This Happened

1. **Margin too small (0.8):**
   - With compactness around 0.45, a margin of 0.8 doesn't push malware far enough
   - Malicious average distance was only 0.57 (less than margin!)

2. **Weak separation penalty:**
   - Loss function weighted compactness and separation equally
   - Model focused on tight clean cluster, ignored malware separation

3. **Class imbalance:**
   - Training: 671 clean vs 269 malicious (2.5:1 ratio)
   - Model biased toward clean classification

## Fixes Applied

### Fix 1: Increase Margin (0.8 → 2.0)
```python
MARGIN = 2.0  # Was 0.8
```

**Why:** Force malicious packages to be at least 2.0 distance away from clean centroid

**Expected:** Malicious distances should increase from ~0.74 to ~1.5-2.0

### Fix 2: Stronger Separation Weight (1x → 2x)
```python
# In compute_contrastive_loss():
loss = loss + 2.0 * margin_loss  # Was 1.0 * margin_loss
```

**Why:** Prioritize pushing malware away over compacting clean cluster

**Expected:** Malicious average distance should increase significantly

### Fix 3: Fixed Distance Calculation
```python
# Changed from squared distance to actual L2 distance:
mal_dist = ((embeddings[mal_mask] - clean_centroid) ** 2).sum(dim=-1).sqrt()
# Was: mal_dist = ((embeddings[mal_mask] - clean_centroid) ** 2).sum(dim=-1)
```

**Why:** Margin should be in same units as actual distance

## How to Retrain

### Option 1: Quick Retrain (Recommended)
```bash
# Delete old checkpoints to avoid confusion
rm -rf models/checkpoints/*
rm models/tgn_v2_best.pt

# Retrain with new settings
make train-split
```

### Option 2: Keep Old Model
```bash
# Backup old model
mv models/tgn_v2_best.pt models/tgn_v2_old.pt
mv models/checkpoints models/checkpoints_old

# Retrain
make train-split
```

## Expected Improvements

### Target Metrics:
```
Distance Statistics (Target):
- Clean packages:     0.5 ± 0.15  (tight cluster)
- Malicious packages: 2.0 ± 0.3   (pushed far away)
- Separation:         1.5 difference (much better!)
- Overlap:            Minimal

Performance (Target):
- Accuracy:  > 85%
- Precision: > 80%
- Recall:    > 70%  ← Main improvement here!
- F1 Score:  > 75%
- ROC-AUC:   > 0.85
```

### What You Should See During Training:

**Before (old training):**
```
Epoch 10/40
  Val Compactness: 0.4464
  Val Mal Distance: 0.5681  ← TOO LOW!
```

**After (new training):**
```
Epoch 10/40
  Val Compactness: 0.3-0.4   ← Similar or slightly higher
  Val Mal Distance: 1.5-2.0  ← MUCH HIGHER!
```

## Evaluation After Retraining

```bash
# Quick evaluation
.venv/bin/python quick_eval.py

# Full evaluation
.venv/bin/python -m scbf.training.evaluate

# Find optimal threshold
.venv/bin/python find_best_threshold.py
```

## Alternative Fixes (If Still Not Good)

### If recall is still low after retraining:

**Option A: Further increase margin**
```python
MARGIN = 3.0  # Even stronger separation
```

**Option B: Add triplet loss**
- Use triplet loss instead of simple contrastive
- Anchor: clean sample
- Positive: another clean sample
- Negative: malicious sample

**Option C: Balanced sampling**
```python
# In train_epoch(), already implemented:
# Oversample minority class (malicious) to match majority
```

**Option D: Lower learning rate**
```python
LEARNING_RATE = 5e-4  # Was 1e-3, slower but more stable
```

**Option E: More epochs with longer patience**
```python
EPOCHS = 60
PATIENCE = 10
```

## Monitoring Training

Watch for these signs of improvement:

✅ **Good signs:**
- Val Mal Distance > 1.5 by epoch 5
- Val Mal Distance keeps increasing
- Val Loss decreasing
- Compactness staying reasonable (0.3-0.5)

⚠️ **Warning signs:**
- Val Mal Distance < 1.0 after epoch 10
- Val Mal Distance stops increasing early
- Compactness exploding (> 1.0)
- Val Loss increasing (overfitting)

## Summary of Changes

| Setting | Before | After | Reason |
|---------|--------|-------|--------|
| Margin | 0.8 | 2.0 | Force larger separation |
| Separation weight | 1.0x | 2.0x | Prioritize pushing malware |
| Distance calc | Squared | L2 | Match margin units |

**Next step:** Retrain and evaluate!

```bash
# Clean start
rm -rf models/checkpoints/* models/tgn_v2_best.pt

# Retrain (1-2 hours)
make train-split

# Evaluate
.venv/bin/python quick_eval.py
```

## Expected Timeline

- **Training:** 1-2 hours (with early stopping)
- **Evaluation:** 5-10 minutes
- **Total:** ~2 hours

## Success Criteria

✅ **Minimum acceptable:**
- Accuracy > 80%
- Recall > 60%
- F1 > 65%

✅ **Good:**
- Accuracy > 85%
- Recall > 75%
- F1 > 75%

✅ **Excellent:**
- Accuracy > 90%
- Recall > 85%
- F1 > 85%

---

**Current Status:** Ready to retrain with improved loss function

**Action:** Run `make train-split` to start improved training
