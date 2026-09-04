# QUT-DV25 Full Dataset Integration (2500+ Samples)

## Overview

This guide explains how to download the **full QUT-DV25 dataset** (14,271 packages) and extract 2500 samples for SCBF training.

**GitHub Repository:** https://github.com/tanzirmehedi/QUT-DV25

---

## Dataset Information

**Full QUT-DV25 Dataset:**
- **Total packages:** 14,271
  - Benign: 7,144 packages
  - Malicious: 7,127 packages
- **Size:** ~450 GB (all traces)
- **Trace types:** Opensnoop, PIDs, Installation, Filetop, TCP, Pattern, Syscalls

**Your current subset:**
- 200 samples (100 benign + 100 malicious)
- Already converted and ready for training

---

## Option 1: Quick Approach (Recommended)

If you want to get started quickly without downloading 450 GB:

### Check the GitHub README First

```bash
# Visit the repository
open https://github.com/tanzirmehedi/QUT-DV25
```

**Look for:**
1. **Google Drive / Zenodo links** - May have pre-packaged subsets
2. **Hugging Face dataset** - Easier download interface
3. **DOI link** - Academic data repository (Zenodo, Figshare, etc.)

### Download Specific Trace Types Only

You don't need ALL trace types. For SCBF, you primarily need:
- ✅ Opensnoop traces (file operations) - **REQUIRED**
- ✅ PIDs (process IDs) - **REQUIRED**
- ⚪ Installation traces (optional, for debugging)
- ❌ TCP, Filetop, Pattern, Syscalls - NOT NEEDED for SCBF

This reduces download from ~450 GB to ~50-100 GB.

---

## Option 2: Full Download & Extract Workflow

### Step 1: Download Full Dataset

#### Method A: Git LFS (if available)

```bash
# Install Git LFS
brew install git-lfs
git lfs install

# Clone repository (~450 GB download!)
git clone --depth 1 https://github.com/tanzirmehedi/QUT-DV25.git QUT-DV25_Full

# This may take several hours on fast internet
```

#### Method B: Manual Download (Recommended)

```bash
# Get download instructions
python3 scripts/download_qutdv25_full.py --method manual
```

Then:
1. Check GitHub README for download links
2. Download from Zenodo/Google Drive/Hugging Face
3. Extract to `QUT-DV25_Full/`

### Step 2: Extract 2500 Sample Subset

```bash
# Extract balanced subset (1250 benign + 1250 malicious)
python3 scripts/extract_qutdv25_subset.py \
    --input QUT-DV25_Full \
    --output QUT-DV25_Datasets \
    --count 2500
```

**What this does:**
- Randomly selects 2500 packages (maintaining 50/50 balance)
- Copies all trace files for selected packages
- Uses seed=42 for reproducibility

**Output:**
```
QUT-DV25_Datasets/
└── QUT-DV_Raw_Datasets/
    ├── QUT-DV25_Benign_Raw_Data_Samples/
    │   ├── QUT-DV25_Opensnoop_Traces/     (1250 files)
    │   ├── QUT-DV25_PIDs/                  (1250 files)
    │   └── ...
    └── QUT-DV25_Malicious_Raw_Data_Samples/
        ├── QUT-DV25_Opensnoop_Traces/     (1250 files)
        ├── QUT-DV25_PIDs/                  (1250 files)
        └── ...
```

### Step 3: Convert to SCBF Format

```bash
# Convert all 2500 samples to SCBF JSONL format
python3 scripts/convert_qutdv25.py
```

**Expected output:**
- ~2450 successfully converted (98% success rate)
- ~50 failed (missing PIDs - normal)
- Output: `data/qut_clean/` and `data/qut_malicious/`

### Step 4: Validate

```bash
python3 scripts/validate_qutdv25.py
```

### Step 5: Train (in Linux VM)

```bash
sudo make train-split
sudo make evaluate
```

---

## Option 3: Incremental Approach

Start small, expand as needed:

### Phase 1: Current (200 samples) ✅
```bash
# Already done!
# 198 converted samples ready for training
```

### Phase 2: Expand to 500 samples
```bash
python3 scripts/extract_qutdv25_subset.py \
    --input QUT-DV25_Full \
    --count 500

python3 scripts/convert_qutdv25.py
```

### Phase 3: Expand to 1000 samples
```bash
python3 scripts/extract_qutdv25_subset.py \
    --input QUT-DV25_Full \
    --count 1000

python3 scripts/convert_qutdv25.py
```

### Phase 4: Full 2500 samples
```bash
python3 scripts/extract_qutdv25_subset.py \
    --input QUT-DV25_Full \
    --count 2500

python3 scripts/convert_qutdv25.py
```

**Advantage:** Test model improvement at each stage.

---

## Dataset Size Projections

| Samples | Clean | Malicious | Total | Events | Training Time (est.) |
|---------|-------|-----------|-------|--------|---------------------|
| Current | 165 | 199 | 364 | 4.3M | ~15 min |
| 500 | 250 | 250 | 500 | ~10M | ~20 min |
| 1000 | 500 | 500 | 1000 | ~20M | ~30 min |
| 2500 | 1250 | 1250 | 2500 | ~50M | ~60 min |
| 5000 | 2500 | 2500 | 5000 | ~100M | ~2 hours |

*Estimates based on average 20,000 events/sample and TGN training speed*

---

## Disk Space Requirements

### For Download

| Component | Size |
|-----------|------|
| Full dataset (all traces) | ~450 GB |
| Opensnoop + PIDs only | ~50-100 GB |
| Extracted 2500 subset | ~30-50 GB |
| Converted JSONL (2500) | ~10-15 GB |

### For Training

| Phase | Disk Space Needed |
|-------|-------------------|
| Raw dataset download | 450 GB |
| Extracted subset | 50 GB |
| Converted JSONL | 15 GB |
| Model checkpoints | 5 GB |
| **Total recommended** | **500+ GB free** |

---

## Quick Commands Reference

### Download Options

```bash
# Get manual download instructions
python3 scripts/download_qutdv25_full.py --method manual

# Or use Git LFS (if confident)
git clone https://github.com/tanzirmehedi/QUT-DV25.git QUT-DV25_Full
```

### Extract Subset

```bash
# 2500 samples (balanced)
python3 scripts/extract_qutdv25_subset.py \
    --input QUT-DV25_Full \
    --output QUT-DV25_Datasets \
    --count 2500

# 1000 samples
python3 scripts/extract_qutdv25_subset.py \
    --input QUT-DV25_Full \
    --count 1000

# Custom seed for different selection
python3 scripts/extract_qutdv25_subset.py \
    --input QUT-DV25_Full \
    --count 2500 \
    --seed 123
```

### Convert & Train

```bash
# Convert
python3 scripts/convert_qutdv25.py

# Validate
python3 scripts/validate_qutdv25.py

# Train (in Linux VM)
sudo make train-split
sudo make evaluate
```

---

## Expected Performance Improvement

With 2500 samples vs. current 364:

| Metric | Current (364) | With 2500 | Improvement |
|--------|---------------|-----------|-------------|
| Training samples | ~255 | ~1750 | **6.8x more** |
| Total events | 4.3M | ~50M | **11.6x more** |
| Expected test F1 | 0.85-0.90 | 0.92-0.95 | **+5-7%** |
| Generalization | Good | Excellent | Better robustness |
| Rare pattern coverage | Limited | Comprehensive | Detect more attacks |

---

## Troubleshooting

### "Dataset too large to download"

**Solution 1:** Download only Opensnoop + PIDs (skip other traces)
**Solution 2:** Use cloud VM with more storage
**Solution 3:** Download incrementally (500 at a time)

### "Not enough disk space"

Free up space:
```bash
# Remove temporary files
rm -rf /tmp/*

# Remove old Docker images
docker system prune -a

# Remove large unused files
du -sh * | sort -h | tail -20
```

### "Download too slow"

- Use university/institution connection (usually faster)
- Download overnight
- Consider Zenodo/Google Drive links (may be faster than Git LFS)

### "Extraction fails"

Check dataset structure:
```bash
ls -la QUT-DV25_Full/QUT-DV_Raw_Datasets/
```

Should contain:
- `QUT-DV25_Benign_Raw_Data_Samples/`
- `QUT-DV25_Malicious_Raw_Data_Samples/`

---

## Alternative: Request Pre-processed Dataset

**Contact the authors** to ask if they have a pre-processed subset:

- **Email:** Check GitHub profile or paper authors
- **Request:** "Pre-converted subset of 2500 samples for behavioral analysis"
- **Benefit:** Skip download/extraction, get ready-to-use data

---

## Next Steps

**Recommended workflow:**

1. ✅ **Use current 364 samples to train baseline model**
   ```bash
   sudo make train-split
   sudo make evaluate
   ```

2. **Check GitHub for easier download options**
   - Zenodo link
   - Google Drive link
   - Hugging Face dataset

3. **Download subset (500-1000 samples first)**
   - Test improvement before committing to full 2500

4. **If results good, expand to full 2500**

5. **Compare model performance at each stage**

---

## Contact & Resources

- **GitHub:** https://github.com/tanzirmehedi/QUT-DV25
- **Paper:** Search "QUT-DV25 arxiv" for the academic paper
- **Authors:** Check GitHub for contact information

---

**Ready to proceed?**

**Option A (Start training now):**
```bash
# Use your current 198 converted samples
sudo make train-split  # In Linux VM
```

**Option B (Get more data first):**
```bash
# Check GitHub for download options
open https://github.com/tanzirmehedi/QUT-DV25
```

Choose based on your disk space and internet speed!
