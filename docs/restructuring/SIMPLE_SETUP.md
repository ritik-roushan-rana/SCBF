# SCBF Simple Setup Guide

**You provide the dataset, we provide the structure.**

## What You Need

**IMPORTANT: Training needs individual trace files!**

Your dataset files:
- ✅ **Individual traces/** (REQUIRED for training)
  - One JSONL file per package
  - Format: `package-version.jsonl`
  - Example: `requests-2.28.0.jsonl`, `numpy-1.24.1.jsonl`
  
- ⚠️ **Aggregated data/** (optional, not used by training)
  - `malware.jsonl` - All events combined
  - `benign.jsonl` - All events combined
  - Good for: Analysis, archiving, statistics
  - NOT used by: Training (needs individual files)

## Quick Setup

```bash
# 1. Create directory structure
make prepare-structure

# 2. Place your individual trace files (REQUIRED)
cp /your/path/malware-traces/*.jsonl data/zenodo_13746167/malware/traces/
cp /your/path/benign-traces/*.jsonl data/zenodo_13746167/benign/traces/

# 3. (Optional) Place aggregated files
cp /your/path/malware.jsonl data/zenodo_13746167/malware/data/
cp /your/path/benign.jsonl data/zenodo_13746167/benign/data/

# 4. Validate
make validate-data
# Should output: ✅ DATASET VALIDATION PASSED

# 5. Train
sudo make train-split

# 6. Done!
sudo make scan PKG=requests
```

## Directory Structure

After `make prepare-structure`, you get:

```
data/
└── zenodo_13746167/
    ├── malware/
    │   ├── data/          ← Place malware.jsonl here
    │   └── traces/        ← Place individual traces here (optional)
    │
    └── benign/
        ├── data/          ← Place benign.jsonl here
        └── traces/        ← Place individual traces here (optional)
```

**That's it!** Clean and simple.

## What's Stored

✅ **ONLY behavioral traces (JSONL text files)**
- Syscall events (exec, open, connect)
- Timestamps, PIDs, file paths
- Package metadata (name, version, label)

❌ **NEVER package binaries or malware**
- No .whl, .tar.gz, .zip files
- No extracted source code
- No actual malware samples
- Repository stays safe

## Expected File Format

Your JSONL files should look like:

```json
{"type":"exec","pid":123,"ppid":100,"comm":"python3","ts":1666270998000,"package":"requests","version":"2.28.0","label":"benign"}
{"type":"open","pid":123,"fname":"/tmp/site-packages/requests/__init__.py","ts":1666270998001,"package":"requests","version":"2.28.0","label":"benign"}
```

**One event per line, NOT pretty-printed JSON.**

## Validation Checks

`make validate-data` verifies:
- ✅ Files exist in correct locations
- ✅ JSONL format valid
- ✅ Required fields present (type, pid, ts, package, version, label)
- ✅ Event types correct (exec, open, connect ONLY)
- ✅ Labels match directory (malicious vs benign)
- ✅ No unexpected fields (dst_ip, dst_port, etc.)
- ✅ PIDs and timestamps valid

## Expected Dataset Stats

After validation, you should see something like:

```
Benign packages: ~1,400
Malware packages: ~450
Total events: ~3-5 million
Avg events/package: ~2,000-3,000

Event Type Distribution:
  open: ~82%
  exec: ~15%
  connect: ~3%
```

## Files Sizes

**Typical sizes:**
- malware.jsonl: 50-150 MB
- benign.jsonl: 150-300 MB
- Individual traces: 50-200 KB each
- **Total: 200-500 MB**

If much larger, check for:
- Duplicate events
- Binary data (not JSONL)
- Pretty-printed JSON (use single-line JSONL)

## Training

After successful validation:

```bash
sudo make train-split
```

**Takes:** ~10-20 minutes  
**Produces:**
- `models/tgn_v2_best.pt` - Trained model
- `models/envelope_v2.npy` - Behavioral centroid
- Training metrics and checkpoints

## Scanning

Use trained model:

```bash
sudo make scan PKG=requests
```

**Output:**
- ALLOW - Normal behavior
- WARN - Suspicious
- BLOCK - Anomalous

## Troubleshooting

### Files not found after placement
```bash
# Did you create structure first?
make prepare-structure

# Check files are in right place
ls -lh data/zenodo_13746167/*/data/*.jsonl
```

### Validation fails
```bash
# Check JSONL format (one object per line)
head -1 data/zenodo_13746167/malware/data/malware.jsonl | jq .

# Verify required fields
grep -m 1 . data/zenodo_13746167/malware/data/malware.jsonl | \
  jq 'keys | sort'
# Should include: ["label", "package", "pid", "ts", "type", "version", ...]
```

### Training fails
```bash
# Ensure validation passed first
make validate-data

# Check you have sudo (needed for eBPF)
sudo echo "Sudo works"

# Check BCC installed (Linux only)
dpkg -l | grep bpfcc-tools
```

## Documentation

- **DATASET_PLACEMENT.md** - Detailed placement guide (you are here)
- **data/README.md** - Event format specifications
- **FINAL_STRUCTURE.md** - Architecture overview
- **RESTRUCTURING_COMPLETE.md** - What was changed

## The Workflow (Again)

```bash
make prepare-structure       # Create directories
# ... copy your files ...
make validate-data          # Check format
sudo make train-split       # Train model
sudo make scan PKG=pkg      # Use model
```

**Simple. Clean. Safe.**

---

**Questions?** Check the documentation files above or open a GitHub issue.

**Ready?** Just place your JSONL files and run!
