# How to Upload and Train on Google Colab

## Option 1: Upload Entire SCBF Folder (Easiest)

### Step 1: Zip the SCBF Folder on Your Mac

```bash
cd /Users/shield/Downloads
zip -r SCBF.zip SCBF/
```

This creates `SCBF.zip` (~2.6 GB) - will take 5-10 minutes.

### Step 2: Upload to Google Colab

1. Go to https://colab.research.google.com
2. Upload the notebook:
   - Click "Upload"
   - Select `/Users/shield/Downloads/scbf/Colab_Training_Complete.ipynb`
3. **Enable GPU:**
   - Runtime > Change runtime type
   - Hardware accelerator: **GPU**
   - Save

### Step 3: Upload SCBF.zip

In Colab:
1. Click folder icon (left sidebar)
2. Click upload button
3. Select `SCBF.zip` from your Downloads
4. Wait for upload (~10-20 minutes)

### Step 4: Extract and Verify

Run this in a Colab cell:
```python
!unzip -q SCBF.zip
!ls -la SCBF/data/zenodo_13746167/benign/traces/ | wc -l
!ls -la SCBF/data/zenodo_13746167/malware/traces/ | wc -l
```

Should show: 959 and 385

### Step 5: Run All Cells

- Click **Runtime > Run all**
- Training starts automatically
- Takes ~30-60 minutes with GPU

---

## Option 2: Use Google Drive (Recommended for Large Files)

### Step 1: Upload to Google Drive

1. Go to https://drive.google.com
2. Create folder: `SCBF_Data`
3. Upload folder: `/Users/shield/Downloads/scbf/data/zenodo_13746167`
4. Wait ~15-20 minutes for upload

### Step 2: In Colab Notebook

Add this cell and run it:

```python
# Mount Google Drive
from google.colab import drive
drive.mount('/content/drive')

# Clone repository
!git clone https://github.com/ritik-roushan-rana/SCBF.git
%cd SCBF

# Copy data from Drive
!mkdir -p data/zenodo_13746167
!cp -r /content/drive/MyDrive/SCBF_Data/zenodo_13746167/* data/zenodo_13746167/

# Verify
!ls data/zenodo_13746167/benign/traces/*.jsonl | wc -l
!ls data/zenodo_13746167/malware/traces/*.jsonl | wc -l
```

### Step 3: Train

```python
!python -m scbf.training.train_with_split
```

---

## Option 3: Upload Only Data (Without Repository)

If you already have code on GitHub:

### Step 1: Zip Only Data

```bash
cd /Users/shield/Downloads/scbf
zip -r data.zip data/zenodo_13746167/
```

Creates `data.zip` (~2.6 GB)

### Step 2: In Colab

```python
# Upload data.zip using file browser

# Clone repository
!git clone https://github.com/ritik-roushan-rana/SCBF.git
%cd SCBF

# Extract data
!unzip -q /content/data.zip

# Verify
!ls data/zenodo_13746167/benign/traces/*.jsonl | wc -l
!ls data/zenodo_13746167/malware/traces/*.jsonl | wc -l

# Train
!python -m scbf.training.train_with_split
```

---

## What You're Uploading

Your SCBF folder contains:
- **Code:** ~10 MB (Python scripts, models)
- **Data:** ~2.6 GB (1,344 trace files)
- **Total:** ~2.6 GB

## Upload Times

| Method | Size | Upload Time | Setup Time | Total |
|--------|------|-------------|------------|-------|
| Full SCBF.zip | 2.6 GB | 10-20 min | 2 min | ~15-25 min |
| Google Drive | 2.6 GB | 15-20 min | 5 min | ~20-25 min |
| Data only | 2.6 GB | 10-20 min | 3 min | ~15-25 min |

## Training Time with GPU

- **Setup:** ~20 minutes
- **Training:** ~30-60 minutes  
- **Evaluation:** ~5 minutes
- **Total:** ~1-1.5 hours

## After Training

The notebook will automatically:
1. Train the model (up to 60 epochs)
2. Evaluate on test set
3. Show results (accuracy, recall, F1)
4. Download `tgn_v2_best.pt`

Place downloaded model in:
```
/Users/shield/Downloads/scbf/models/tgn_v2_best.pt
```

## Troubleshooting

**"Upload failed"**
- File too large? Use Google Drive method
- Slow internet? Upload overnight

**"No GPU available"**
- Runtime > Change runtime type > GPU
- Or try different account/time

**"Files not found"**
- Check paths in notebook match your upload
- Verify extraction: `!ls -la`

**"Out of memory"**
- Use smaller batch size
- Or use Colab Pro ($10/month)

## Summary

**Fastest method:**
1. Zip SCBF folder: `zip -r SCBF.zip SCBF/`
2. Upload to Colab
3. Extract: `!unzip -q SCBF.zip`
4. Run notebook: Runtime > Run all
5. Download trained model

**Total time:** ~1.5 hours (including upload)
