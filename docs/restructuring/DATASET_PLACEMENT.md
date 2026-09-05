# Dataset Placement Guide

**Quick guide for placing your pre-collected dataset into SCBF.**

## TL;DR

```bash
# 1. Create directory structure
make prepare-structure

# 2. Place your files
cp malware.jsonl data/zenodo_13746167/malware/data/
cp benign.jsonl data/zenodo_13746167/benign/data/
cp malware-traces/*.jsonl data/zenodo_13746167/malware/traces/
cp benign-traces/*.jsonl data/zenodo_13746167/benign/traces/

# 3. Validate
make validate-data

# 4. Train
sudo make train-split
```

## Directory Structure

You need to place files here:

```
data/zenodo_13746167/
├── malware/
│   ├── data/
│   │   └── malware.jsonl          ← Place aggregated malware events here
│   └── traces/
│       └── *.jsonl                ← Place individual malware traces here
│
└── benign/
    ├── data/
    │   └── benign.jsonl           ← Place aggregated benign events here
    └── traces/
        └── *.jsonl                ← Place individual benign traces here
```

## File Requirements

### malware.jsonl and benign.jsonl
- **Format:** Event-level JSONL (one event per line)
- **Contents:** All behavioral events from all packages
- **Required fields per event:**
  - `type`: "exec", "open", or "connect"
  - `pid`: Process ID (positive integer)
  - `ts`: Timestamp (positive integer)
  - `package`: Package name
  - `version`: Package version
  - `label`: "malicious" or "benign"

### Trace files (*.jsonl)
- **Format:** Per-package JSONL files
- **Naming:** `<package>-<version>.jsonl` (sanitized)
- **Contents:** Same format as aggregated files, but one package per file
- **Optional:** Can be omitted if you only have aggregated files

## Example Event Format

```json
{"type":"exec","pid":123,"ppid":100,"comm":"python3","ts":1666270998000,"package":"requests","version":"2.28.0","label":"benign"}
{"type":"open","pid":123,"fname":"/tmp/site-packages/requests/__init__.py","ts":1666270998001,"package":"requests","version":"2.28.0","label":"benign"}
{"type":"connect","pid":123,"fname":"connect","ts":1666270998002,"package":"requests","version":"2.28.0","label":"benign"}
```

## Validation

After placing files, validate:

```bash
make validate-data
```

**Expected output:**
```
✅ DATASET VALIDATION PASSED

Dataset Statistics
  Benign packages: 1,432
  Malware packages: 486
  Total events: 4,691,356

Event Type Distribution
  open: 82.4%
  exec: 15.2%
  connect: 2.4%

Validation Results
  Errors: 0
  Warnings: 0
```

**If validation fails:**
- Check JSONL format (one JSON object per line)
- Verify required fields present
- Ensure event types are only: exec, open, connect
- Check labels match directory (malicious vs benign)

## Training

After successful validation:

```bash
sudo make train-split
```

This will:
1. Read your dataset from `data/zenodo_13746167/`
2. Split into train/val/test sets
3. Train TGN encoder
4. Build behavioral envelope
5. Save model to `models/tgn_v2_best.pt`

## What NOT to Include

❌ **Do NOT place:**
- Package binaries (.whl, .tar.gz, .zip)
- Extracted source code
- Malware samples
- Installation artifacts
- Anything except JSONL event traces

✅ **Only place:**
- Behavioral event traces (JSONL text files)
- Syscall logs (exec, open, connect events)

## File Sizes

**Expected sizes (approximate):**
- `malware.jsonl`: 50-150 MB
- `benign.jsonl`: 150-300 MB
- Individual traces: 50-200 KB each
- Total: 200-500 MB

**If your files are much larger:**
- Check for duplicate events
- Verify no binary data included
- Ensure proper JSONL formatting (not pretty-printed JSON)

## Common Issues

### "File does not exist"
```bash
# Make sure you created the structure first
make prepare-structure
```

### "Invalid JSON"
```bash
# Check JSONL format (one object per line, no commas between lines)
head -1 data/zenodo_13746167/malware/data/malware.jsonl | jq .
```

### "Missing required field"
```bash
# Each event must have: type, pid, ts, package, version, label
# Check your event format
```

### "Label mismatch"
```bash
# malware.jsonl events must have "label":"malicious"
# benign.jsonl events must have "label":"benign"
```

## Quick Check

Before training, verify everything is in place:

```bash
# Check files exist
ls -lh data/zenodo_13746167/malware/data/malware.jsonl
ls -lh data/zenodo_13746167/benign/data/benign.jsonl

# Count events
wc -l data/zenodo_13746167/*/data/*.jsonl

# Check format (first line)
head -1 data/zenodo_13746167/malware/data/malware.jsonl | jq .

# Run validation
make validate-data
```

## Next Steps

After successful placement and validation:

1. **Train model:** `sudo make train-split`
2. **Evaluate:** `make evaluate`
3. **Scan packages:** `sudo make scan PKG=requests`
4. **Deploy:** Use trained model for detection

## Questions?

- Check [data/README.md](data/README.md) for detailed format specs
- See [FINAL_STRUCTURE.md](FINAL_STRUCTURE.md) for architecture overview
- Review [DATASET_PREPARATION_GUIDE.md](DATASET_PREPARATION_GUIDE.md) if you need to collect your own data

---

**Remember:** Just place your JSONL files in the right locations, validate, and train. Simple as that!
