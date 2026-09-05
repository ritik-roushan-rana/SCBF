# Train SCBF on Google Colab (FAST with GPU!)

## Why Colab?
- **FREE GPU** - Training will be 10-30x faster
- **~30-60 minutes** instead of 2-3 hours on CPU
- **No local resources** needed

## Prerequisites

You need:
1. Google account
2. Your dataset: `data/zenodo_13746167/` folder

## Step-by-Step Instructions

### 1. Prepare Dataset Locally

First, zip your dataset folder:

```bash
cd /Users/shield/Downloads/scbf
zip -r scbf_data.zip data/zenodo_13746167/
```

This creates `scbf_data.zip` (~2.6 GB).

### 2. Upload to Google Colab

**Option A: Upload Notebook**
1. Go to https://colab.research.google.com
2. Click "Upload" 
3. Upload `SCBF_Training_Colab.ipynb` from this folder

**Option B: Open from GitHub**
1. Push the notebook to your repo first:
   ```bash
   git add SCBF_Training_Colab.ipynb
   git commit -m "Add Colab training notebook"
   git push
   ```
2. Go to https://colab.research.google.com
3. File > Open notebook > GitHub
4. Enter: `ritik-roushan-rana/SCBF`
5. Select `SCBF_Training_Colab.ipynb`

### 3. Enable GPU Runtime

**IMPORTANT:** Use GPU for fast training!

1. In Colab, click: **Runtime > Change runtime type**
2. Set **Hardware accelerator** to **GPU** (T4 or better)
3. Click **Save**

### 4. Upload Dataset to Colab

**Option A: Direct Upload (Slower)**
1. In Colab, click the folder icon (left sidebar)
2. Click upload icon
3. Upload `scbf_data.zip` (takes 5-10 minutes)

**Option B: Google Drive (Faster, Recommended)**
1. Upload `scbf_data.zip` to your Google Drive first
2. In Colab, mount Drive (code in notebook)
3. Copy from Drive to Colab

### 5. Run All Cells

In Colab:
1. Click **Runtime > Run all**
2. Wait for each cell to complete
3. Watch the training progress!

**Training output:**
```
Epoch 1/60
  Train Loss: X.XXXX
  Val Loss: X.XXXX
  Val Mal Distance: X.XXXX  ← Watch this increase!
  
Epoch 2/60
  ...

Early stopping at epoch XX
```

### 6. Check Results

After training completes, the evaluation cell shows:

```
DISTANCE STATISTICS
Clean distances: mean=X.XXXX, std=X.XXXX
Malicious distances: mean=X.XXXX, std=X.XXXX

TEST SET RESULTS
Accuracy:  XX.XX%
Precision: XX.XX%
Recall:    XX.XX%
F1 Score:  XX.XX%
```

**What to look for:**
- ✅ Malicious distance > 1.5 (good separation)
- ✅ Accuracy > 85%
- ✅ Recall > 70%
- ✅ F1 > 75%

### 7. Download Trained Model

The last cell downloads `tgn_v2_best.pt` to your computer.

Place it in: `/Users/shield/Downloads/scbf/models/tgn_v2_best.pt`

### 8. Use Model Locally

After downloading the model:

```bash
cd /Users/shield/Downloads/scbf

# Evaluate locally
.venv/bin/python quick_eval.py

# Build envelope
python -m scbf.training.build_envelope

# Scan packages
make scan PKG=requests
```

## Troubleshooting

### "No GPU available"
- Change runtime type: Runtime > Change runtime type > GPU
- Try again or use different Google account

### "Upload failed"
- Try Google Drive method instead
- Or split zip into smaller parts

### "Out of memory"
- Reduce batch size (uncommon with 1,344 packages)
- Or use smaller dataset for testing

### "Training crashed"
- Check error message in Colab
- Try restarting runtime: Runtime > Restart runtime

## Expected Timeline (with GPU)

| Step | Time |
|------|------|
| Setup & Upload | 10-15 min |
| Training (60 epochs) | 30-60 min |
| Evaluation | 5 min |
| Download model | 1 min |
| **Total** | **~1 hour** |

Compare to local CPU: 2-3 hours!

## Alternative: Use Colab Pro

If you need:
- Longer runtimes (12+ hours)
- Better GPUs (A100, V100)
- More memory

Consider **Colab Pro** ($10/month):
- Faster training (~15-30 min)
- Priority GPU access
- Longer sessions

## What Gets Trained

**Model:**
- TGN (Temporal Graph Network)
- 3-component contrastive loss
- Margin: 3.0
- Learning rate: 5e-4

**Training:**
- 70/15/15 train/val/test split
- Up to 60 epochs
- Early stopping with patience=10
- Class-balanced batches

**Output:**
- Best model: `tgn_v2_best.pt`
- Checkpoints: `models/checkpoints/`
- Split info: `split_info.json`

## After Training

Once you have the trained model locally:

1. **Evaluate:**
   ```bash
   .venv/bin/python quick_eval.py
   ```

2. **Build envelope:**
   ```bash
   python -m scbf.training.build_envelope
   ```

3. **Scan packages:**
   ```bash
   make scan PKG=requests
   make scan PKG=django
   ```

4. **Deploy:**
   - Use `models/tgn_v2_best.pt` and `models/envelope_v2.npy`
   - Integrate into CI/CD pipeline

## Summary

**To train on Colab:**
1. Zip dataset: `zip -r scbf_data.zip data/`
2. Upload `SCBF_Training_Colab.ipynb` to Colab
3. Enable GPU runtime
4. Upload data (or use Google Drive)
5. Run all cells
6. Download trained model
7. Use locally

**Benefits:**
- ✅ 10-30x faster with GPU
- ✅ Free (or $10/month for Pro)
- ✅ No local resources used
- ✅ Same results as local training

**Questions?** Check the notebook - it has detailed comments and error handling!
