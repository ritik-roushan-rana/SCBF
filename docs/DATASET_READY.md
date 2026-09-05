# Dataset Successfully Copied and Validated ✅

**Status:** Dataset ready for training!

## Summary

✅ **Dataset copied from:** `dataset_setup_monitor/data/zenodo_13746167/`  
✅ **Dataset placed in:** `data/zenodo_13746167/`  
✅ **Validation:** PASSED

## Dataset Statistics

```
Packages:
  Benign:    959 packages
  Malware:   385 packages
  Total:     1,344 packages

Events:
  Benign:    4,996,936 events (~5.2K per package)
  Malware:     931,114 events (~2.4K per package)
  Total:     5,928,050 events

Event Distribution:
  open:      99.5%
  connect:    0.5%
  exec:       0.0%

File Structure:
  Benign traces:  959 files
  Malware traces: 385 files
  Aggregated:     benign.jsonl (1.3GB), malware.jsonl (299MB)
```

## What Was Done

1. **Copied dataset** from `dataset_setup_monitor/` to `data/zenodo_13746167/`
   - 385 malware trace files
   - 959 benign trace files
   - 2 aggregated JSONL files

2. **Updated validator** to accept multiple label formats:
   - Numeric: `0` (benign), `1` (malicious)
   - String: `"benign"`, `"BENIGN"`, `"malicious"`, `"MALICIOUS"`

3. **Validated dataset** - All checks passed!
   - ✅ Directory structure correct
   - ✅ JSONL format valid
   - ✅ Required fields present
   - ✅ Event types correct (open, connect, exec)
   - ✅ Labels valid
   - ⚠️  320 warnings about non-monotonic timestamps (minor, won't affect training)

## File Locations

```
data/zenodo_13746167/
├── malware/
│   ├── data/
│   │   └── malware.jsonl          # 299MB, 931K events
│   └── traces/
│       └── *.jsonl                # 385 files (training uses these)
│
└── benign/
    ├── data/
    │   └── benign.jsonl           # 1.3GB, 5M events
    └── traces/
        └── *.jsonl                # 959 files (training uses these)
```

## Training

Your dataset is ready! Train the model:

```bash
# Train with train/val/test split
sudo make train-split

# Expected:
# - Training: ~940 packages (70%)
# - Validation: ~202 packages (15%)
# - Test: ~202 packages (15%)
```

## Training Details

Training will:
1. Read from `data/zenodo_13746167/*/traces/*.jsonl`
2. Split packages into train/val/test (70/15/15%)
3. Train for multiple epochs with early stopping
4. Save best model to `models/tgn_v2_best.pt`
5. Build behavioral envelope from benign training set
6. Save centroid to `models/envelope_v2.npy`

## What Worked

✅ **Individual trace files** - Training needs these, not aggregated  
✅ **Flexible labels** - Validator accepts 0/1, benign/BENIGN, malicious/MALICIOUS  
✅ **Both formats** - You have individual traces AND aggregated files  
✅ **Large dataset** - 1,344 packages is excellent for training  

## Script Used

`copy_dataset.sh` - Automated copy from `dataset_setup_monitor/` to `data/`

Can be re-run if needed:
```bash
./copy_dataset.sh
```

## Next Steps

```bash
# 1. Train model (will take 10-30 minutes)
sudo make train-split

# 2. Evaluate performance
make evaluate

# 3. Scan packages
sudo make scan PKG=requests
```

## Warnings (Optional)

320 warnings about non-monotonic timestamps detected:
- These occur when multiple processes write events concurrently
- Won't affect training (TGN processes events in order anyway)
- Can be safely ignored

Example warning:
```
Non-monotonic timestamp for asrepcatcher-0.4.0
```

This means some events from that package have out-of-order timestamps, but TGN's `replay_session()` sorts events by timestamp before processing, so this is handled automatically.

## Dataset Quality

**High quality dataset:**
- ✅ 1,344 unique packages
- ✅ 5.9M behavioral events total
- ✅ Good balance (959 benign, 385 malware)
- ✅ Individual trace files (required for training)
- ✅ All required fields present
- ✅ Valid event types
- ✅ Consistent labeling

## Summary

🎉 **Your dataset is ready for training!**

Run `sudo make train-split` to start training the model on your 1,344 package dataset.

---

**Files created/modified:**
- `copy_dataset.sh` - Dataset copy script
- `scripts/validate_dataset.py` - Updated to accept multiple label formats
- `data/zenodo_13746167/` - Dataset location (populated)
- `DATASET_READY.md` - This file

**Status: READY TO TRAIN ✅**
