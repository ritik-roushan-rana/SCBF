# SCBF Final Repository Structure ✅

**Last Updated:** 2026-09-05  
**Status:** Ready for dataset placement

## Final Directory Structure

```
data/
└── zenodo_13746167/              # Final dataset (Zenodo publication)
    ├── malware/
    │   ├── data/
    │   │   └── malware.jsonl     # Aggregated malware events
    │   └── traces/
    │       └── *.jsonl           # Per-package malware traces
    │
    └── benign/
        ├── data/
        │   └── benign.jsonl      # Aggregated benign events
        └── traces/
            └── *.jsonl           # Per-package benign traces
```

**That's it!** Just the final dataset location. No intermediate directories.

## What's Stored

### ✅ STORED (Safe behavioral data)
- **Event traces (JSONL)**: Syscall behavioral logs
  - exec, open, connect events
  - PIDs, timestamps, file paths
  - Package metadata (name, version, label)
  
- **Aggregated datasets**: Combined event streams
  - `malware.jsonl`: All malicious package events
  - `benign.jsonl`: All benign package events

### ❌ NOT STORED (Safety measure)
- **NO package binaries** (.whl, .tar.gz, .zip)
- **NO extracted files** (source code, compiled binaries)
- **NO malware samples** (actual malicious code)
- **NO installation artifacts**

**Why:** We only need behavioral fingerprints (event logs), not the actual packages. This keeps the repository safe, lightweight, and focused on behavioral analysis.

## Data Format

Each JSONL file contains behavioral events (one per line):

```json
{"type":"exec","pid":123,"ppid":100,"comm":"python3","ts":1666270998000,"package":"requests","version":"2.28.0","label":"benign"}
{"type":"open","pid":123,"fname":"/tmp/site-packages/requests/__init__.py","ts":1666270998001,"package":"requests","version":"2.28.0","label":"benign"}
{"type":"connect","pid":123,"fname":"connect","ts":1666270998002,"package":"requests","version":"2.28.0","label":"benign"}
```

## Complete Workflow

```bash
# 1. Create structure
make prepare-structure

# 2. Place your dataset files
cp /path/to/malware.jsonl data/zenodo_13746167/malware/data/
cp /path/to/benign.jsonl data/zenodo_13746167/benign/data/
cp /path/to/traces/*.jsonl data/zenodo_13746167/*/traces/

# 3. Validate
make validate-data
# → Checks format, integrity, no unexpected data

# 4. Train
sudo make train-split

# 5. Scan
sudo make scan PKG=requests
```

## Size Estimates

### Behavioral Traces Only
- **Per-package trace**: ~50-200 KB (JSONL text)
- **1500 benign packages**: ~75-300 MB
- **500 malicious packages**: ~25-100 MB
- **Total raw traces**: ~100-400 MB
- **Compressed**: ~20-80 MB

### If We Stored Packages (NOT DOING THIS)
- **Per package binary**: 1-50 MB
- **1500 benign packages**: 1.5-75 GB
- **500 malicious packages**: 0.5-25 GB
- **Total**: 2-100 GB 🚫 TOO LARGE

**Conclusion:** Storing only traces reduces dataset size by 10-100x while preserving all behavioral information needed for detection.

## Safety Benefits

### 1. No Malware Risk
- Repository contains NO executable code from malicious packages
- Safe to clone, share, and publish
- No risk of accidental execution

### 2. Lightweight
- Behavioral traces are small text files
- Easy to download, version control, and distribute
- Fast training iterations

### 3. Privacy-Preserving
- Only syscall-level events captured
- No source code, credentials, or secrets
- Suitable for public Zenodo release

### 4. Reproducible
- Anyone can re-collect traces from same packages
- Event format is deterministic
- Training results are reproducible

## Validation Checklist

Before training, verify:

- [x] Directory structure exists (no `extracted/` dirs)
- [ ] `data/zenodo_13746167/malware/data/malware.jsonl` exists
- [ ] `data/zenodo_13746167/benign/data/benign.jsonl` exists
- [ ] Trace files in `data/zenodo_13746167/*/traces/`
- [ ] NO `.whl`, `.tar.gz`, `.zip` files in data/
- [ ] NO executable binaries in data/
- [ ] NO extracted source code in data/
- [ ] `make validate-data` passes (0 errors)
- [ ] Event types are exec, open, connect ONLY
- [ ] File sizes reasonable (~100-400 MB total)

## What Happened

### Removed ❌
- `data/zenodo_13746167/malware/extracted/` directory
- `data/zenodo_13746167/benign/extracted/` directory
- References to `extracted/` in documentation
- `.gitignore` pattern for `extracted/`

### Updated ✅
- Makefile: `make prepare-structure` creates only `{data,traces}` dirs
- data/README.md: Documents trace-only storage
- DATASET_PREPARATION_GUIDE.md: Emphasizes trace-only approach
- REPOSITORY_ANALYSIS.md: Reflects final structure
- .gitignore: Removed `extracted/` pattern (not needed)

## Next Steps

Your workflow remains the same:

```bash
# Collect traces (only behavioral logs captured)
sudo python scripts/collect_clean_data.py
sudo python scripts/collect_malicious_data.py

# Aggregate
python scripts/aggregate_jsonl.py

# Validate (will check no binaries present)
python scripts/validate_dataset.py

# Train
sudo make train-split
```

## Summary

✅ **Repository is clean and safe**
- Only behavioral traces (JSONL text files)
- No package binaries, no malware samples
- Lightweight, shareable, reproducible
- Ready for Zenodo publication

✅ **Workflow unchanged**
- Collection scripts work as before
- Aggregation and validation ready
- Training pipeline compatible

✅ **Safety improved**
- No risk of malware execution
- Safe to publish on GitHub/Zenodo
- Compliant with repository policies

---

**Status: READY FOR BEHAVIORAL TRACE COLLECTION**

Collect data knowing that only safe behavioral fingerprints (event logs) will be stored, not actual package code or binaries.
