# Training V3 - Improved Loss Function

## Status: RUNNING IN BACKGROUND

**PID:** Check with `cat training.pid`  
**Log:** `tail -f training_v3.log`  
**Started:** ~22:06

## Previous Attempts

### V1 (Original - margin=0.8)
- **Result:** Accuracy 71.78%, Recall 8.62%
- **Problem:** Margin too small, weak separation
- **Mal distance:** 0.57 (too close to clean 0.65)

### V2 (margin=2.0, 2x weight)
- **Result:** Accuracy 70.30%, Recall 1.72% (WORSE!)
- **Problem:** Still insufficient separation
- **Mal distance:** 0.86 (still overlaps with clean 0.78)

## V3 Changes (Current)

### New Loss Function
```python
Loss = compactness + 3.0 * margin_loss + 2.0 * gap_loss

Components:
1. Compactness: Pull clean samples tight
2. Separation (3x weight): Push malicious away strongly  
3. Gap loss (2x weight): Force gap between farthest clean and closest malicious
```

### New Hyperparameters
| Parameter | V1 | V2 | V3 (Current) |
|-----------|----|----|--------------|
| Margin | 0.8 | 2.0 | **3.0** |
| Learning Rate | 1e-3 | 1e-3 | **5e-4** |
| Epochs | 40 | 40 | **60** |
| Patience | 5 | 5 | **10** |
| Separation Weight | 1.0x | 2.0x | **3.0x** |
| Gap Loss Weight | - | - | **2.0x (NEW)** |

### Key Improvements

**1. Gap Loss (NEW)**
```python
gap = min_mal_dist - max_clean_dist
gap_loss = max(0, margin - gap)
```
- Forces separation between classes
- Ensures even the closest malicious is far from farthest clean
- Prevents overlap

**2. Stronger Separation Weight (3x)**
- Was 2x, now 3x
- Prioritizes pushing malware away

**3. Lower Learning Rate (5e-4)**
- More stable convergence
- Slower but more reliable

**4. More Patience (10 epochs)**
- Give model more time to improve
- Longer training may be needed for strong separation

## What to Watch

### During Training

**Good signs ✅:**
```
Epoch 10/60
  Val Compactness: 0.4-0.5
  Val Mal Distance: 1.5+  ← Target!
  Val Gap: 0.5+           ← NEW metric
```

**Warning signs ⚠️:**
```
Epoch 20/60
  Val Mal Distance: <1.0  ← Still not enough
  Val Gap: <0.0           ← Classes overlapping
```

### Monitor Commands

```bash
# Check if running
ps -p $(cat training.pid)

# Watch log (when it starts writing)
tail -f training_v3.log

# Check checkpoints
ls -lt models/checkpoints/*.pt

# Quick check progress
ls models/checkpoints/tgn_epoch*.pt | wc -l
```

## Expected Timeline

- **Duration:** 2-3 hours (longer due to slower LR and more epochs)
- **Early stopping:** Likely around epoch 20-30
- **First checkpoint:** ~5-10 minutes

## After Training Completes

```bash
# Evaluate
.venv/bin/python quick_eval.py

# Find optimal threshold
.venv/bin/python find_best_threshold.py
```

## Target Metrics

### Minimum Acceptable
- Mal Distance: > 1.5
- Accuracy: > 80%
- Recall: > 60%
- F1: > 65%

### Good
- Mal Distance: > 2.0
- Accuracy: > 85%
- Recall: > 75%
- F1: > 75%

### Excellent
- Mal Distance: > 2.5
- Accuracy: > 90%
- Recall: > 85%
- F1: > 85%

## If V3 Still Doesn't Work

### Option 1: Normalize Embeddings
Force embeddings to unit sphere - makes distances more meaningful

### Option 2: Use Different Architecture
- Add more TGN layers
- Use attention mechanism
- Different aggregation

### Option 3: Data Augmentation
- Temporal jittering
- Event sampling
- Synthetic malware variations

### Option 4: Different Loss Function
- Triplet loss
- ArcFace/CosFace (angular margin)
- Focal loss

### Option 5: Class Balancing
- Oversample malicious more aggressively
- Use class weights in loss
- SMOTE-like behavioral synthesis

## Current Status

**Training:** RUNNING  
**Check:** `tail -f training_v3.log` (once it starts outputting)  
**ETA:** 2-3 hours  

**Note:** Log file may be buffered - checkpoints are more reliable indicator of progress.

---

**Will update when training completes!**
