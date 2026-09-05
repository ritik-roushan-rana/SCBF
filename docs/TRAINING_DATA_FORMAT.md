# What Data Format Training Needs ⚠️

## TL;DR

**Training needs INDIVIDUAL TRACE FILES (one per package), NOT aggregated JSONL!**

```bash
# ✅ REQUIRED for training
data/zenodo_13746167/malware/traces/
├── package1-v1.0.jsonl      # One file per package
├── package2-v2.1.jsonl
└── ...

data/zenodo_13746167/benign/traces/
├── requests-2.28.0.jsonl
├── numpy-1.24.1.jsonl
└── ...

# ⚠️ OPTIONAL (not used by training)
data/zenodo_13746167/malware/data/malware.jsonl  # All events combined
data/zenodo_13746167/benign/data/benign.jsonl    # All events combined
```

## Why Individual Files?

Training needs to:
1. **Split by package** - Divide into train/val/test sets (70/15/15%)
2. **Process independently** - Each package gets its own behavioral "DNA" vector
3. **Maintain boundaries** - Cannot split aggregated file by package

## What You Should Provide

### Option 1: Individual Traces Only (Minimum)
```
data/zenodo_13746167/
├── malware/traces/
│   ├── pkg1-v1.0.jsonl     ← Training reads these
│   ├── pkg2-v2.1.jsonl
│   └── ... (450-500 files)
└── benign/traces/
    ├── requests-2.28.0.jsonl  ← Training reads these
    ├── numpy-1.24.1.jsonl
    └── ... (1400-1500 files)
```

### Option 2: Both Individual + Aggregated (Recommended)
```
data/zenodo_13746167/
├── malware/
│   ├── data/
│   │   └── malware.jsonl   ← For analysis/archiving
│   └── traces/
│       └── *.jsonl          ← Training reads these
└── benign/
    ├── data/
    │   └── benign.jsonl    ← For analysis/archiving
    └── traces/
        └── *.jsonl          ← Training reads these
```

## File Format

Each trace file contains events for ONE package:

```json
{"type":"exec","pid":123,"ppid":100,"comm":"python3","ts":1666270998000,"package":"requests","version":"2.28.0","label":"benign"}
{"type":"open","pid":123,"fname":"/tmp/site-packages/requests/__init__.py","ts":1666270998001,"package":"requests","version":"2.28.0","label":"benign"}
{"type":"connect","pid":123,"fname":"connect","ts":1666270998002,"package":"requests","version":"2.28.0","label":"benign"}
```

**File naming convention:**
- `<package>-<version>.jsonl`
- Sanitized (no `/` or spaces)
- Examples: `requests-2.28.0.jsonl`, `numpy-1.24.1.jsonl`

## Training Workflow

```python
# Internally, train_with_split.py does:
clean_paths = glob.glob("data/zenodo_13746167/benign/traces/*.jsonl")  # Get file list
mal_paths = glob.glob("data/zenodo_13746167/malware/traces/*.jsonl")

# Split files into sets
train, val, test = split_packages(clean_paths, mal_paths, ratios=[0.7, 0.15, 0.15])

# Process each file independently
for file_path in train:
    events = load_jsonl(file_path)
    dna_vector = model.process(events)
    # ...train on dna_vector
```

## Common Mistakes

### ❌ WRONG: Only aggregated files
```
data/zenodo_13746167/malware/data/malware.jsonl  ← Can't split by package
data/zenodo_13746167/benign/data/benign.jsonl    ← Can't split by package
```

**Error:** Training will find 0 files, fail immediately.

### ❌ WRONG: All events in one trace file
```
data/zenodo_13746167/malware/traces/all-malware.jsonl  ← Contains 500 packages
data/zenodo_13746167/benign/traces/all-benign.jsonl    ← Contains 1500 packages
```

**Error:** Training treats this as 1 malware + 1 benign package (wrong!).

### ✅ CORRECT: Individual trace files
```
data/zenodo_13746167/malware/traces/
├── pkg1-v1.0.jsonl      ← 1 package
├── pkg2-v2.1.jsonl      ← 1 package
└── ... (500 files total)
```

**Success:** Training sees 500 malware packages, splits correctly.

## How to Convert Aggregated → Individual

If you only have aggregated files, split them by package:

```python
import json
from collections import defaultdict

# Read aggregated file
packages = defaultdict(list)
with open("data/zenodo_13746167/malware/data/malware.jsonl") as f:
    for line in f:
        event = json.loads(line)
        pkg_key = f"{event['package']}-{event['version']}"
        packages[pkg_key].append(event)

# Write individual files
for pkg_key, events in packages.items():
    with open(f"data/zenodo_13746167/malware/traces/{pkg_key}.jsonl", "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

print(f"Created {len(packages)} individual trace files")
```

## Validation

Check your dataset structure:

```bash
# Count files (should be ~450-500 malware, ~1400-1500 benign)
find data/zenodo_13746167/malware/traces/ -name "*.jsonl" | wc -l
find data/zenodo_13746167/benign/traces/ -name "*.jsonl" | wc -l

# Verify training can find them
python -c "import glob; print(len(glob.glob('data/zenodo_13746167/*/traces/*.jsonl')))"
# Should print: ~1900-2000

# Run validation
make validate-data
```

## Expected Numbers

After placing files:
- **Malware traces:** 450-500 files (~50-200 KB each)
- **Benign traces:** 1400-1500 files (~50-200 KB each)
- **Total size:** ~200-400 MB
- **Files per directory:** One `.jsonl` per package

Training will then:
- Split into train/val/test: 70% / 15% / 15%
- Example: 500 malware → 350 train + 75 val + 75 test
- Example: 1400 benign → 980 train + 210 val + 210 test

## Summary

✅ **You need:** Individual trace files in `traces/` directories  
⚠️ **Optional:** Aggregated files in `data/` directories (not used by training)  
❌ **Don't provide:** Only aggregated files (training will fail)

**Place your individual traces, then train!**

```bash
# Place traces
cp malware-traces/*.jsonl data/zenodo_13746167/malware/traces/
cp benign-traces/*.jsonl data/zenodo_13746167/benign/traces/

# Train
sudo make train-split
```

---

**Questions?** See `docs/restructuring/SIMPLE_SETUP.md` or `data/README.md`
