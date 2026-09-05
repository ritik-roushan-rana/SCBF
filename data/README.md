# SCBF Dataset Directory

This directory contains behavioral trace data for training and evaluation.

## ⚠️ IMPORTANT: What Training Needs

**Training requires INDIVIDUAL TRACE FILES**, not aggregated JSONL!

```
data/zenodo_13746167/
├── malware/
│   └── traces/              ← Training reads from here!
│       ├── pkg1-v1.0.jsonl  ← One file per package
│       ├── pkg2-v2.1.jsonl
│       └── ...
└── benign/
    └── traces/              ← Training reads from here!
        ├── requests-2.28.0.jsonl
        ├── numpy-1.24.1.jsonl
        └── ...
```

**Why individual files?**
- Training splits packages into train/val/test sets (70/15/15%)
- Each package processed independently for its behavioral "DNA"
- Cannot split aggregated file by package boundary

**The aggregated files are optional:**
- `data/malware.jsonl` - All events combined (for analysis)
- `data/benign.jsonl` - All events combined (for analysis)
- Training does NOT read these!

## Directory Structure

```
data/
└── zenodo_13746167/
    ├── malware/
    │   ├── data/
    │   │   └── malware.jsonl     # Aggregated (optional, not used by training)
    │   └── traces/               # ← TRAINING READS FROM HERE
    │       ├── pkg1-v1.0.jsonl   # Individual package traces
    │       ├── pkg2-v2.1.jsonl
    │       └── ...
    │
    └── benign/
        ├── data/
        │   └── benign.jsonl      # Aggregated (optional, not used by training)
        └── traces/               # ← TRAINING READS FROM HERE
            ├── requests-2.28.0.jsonl
            ├── numpy-1.24.1.jsonl
            └── ...
```

**Training workflow:**
1. Scans `data/zenodo_13746167/*/traces/*.jsonl`
2. Splits files into train/val/test (70/15/15%)
3. Processes each file independently
4. Generates behavioral DNA per package

## Event Format

Each `.jsonl` file contains one event per line in JSON format.

### Event Types

**Exec event** (process execution):
```json
{
  "type": "exec",
  "pid": 12345,
  "ppid": 12300,
  "comm": "python3",
  "ts": 1666270998000000000,
  "package": "requests",
  "version": "2.28.0",
  "artifact": "requests-2.28.0.tar.gz",
  "label": "benign"
}
```

**Open event** (file access):
```json
{
  "type": "open",
  "pid": 12345,
  "fname": "/tmp/site-packages/requests/__init__.py",
  "ts": 1666270998001000000,
  "package": "requests",
  "version": "2.28.0",
  "artifact": "requests-2.28.0.tar.gz",
  "label": "benign"
}
```

**Connect event** (network activity):
```json
{
  "type": "connect",
  "pid": 12345,
  "fname": "connect",
  "ts": 1666270998002000000,
  "package": "requests",
  "version": "2.28.0",
  "artifact": "requests-2.28.0.tar.gz",
  "label": "benign"
}
```

### Required Fields

All events:
- `type`: Event type (exec, open, connect)
- `pid`: Process ID
- `ts`: Timestamp (nanoseconds since epoch)

Additional fields:
- `ppid`: Parent process ID (exec events only)
- `comm`: Command name (exec events)
- `fname`: File path (open) or "connect" (connect events)

### Package Metadata

Added by collector:
- `package`: Package name
- `version`: Package version
- `artifact`: Original artifact filename
- `label`: "benign" or "malicious"

## JSONL Design

### Event-Level JSONL
Each line represents ONE behavioral event, not one package.

A single package may generate thousands of events:
```
Line 1: {"type":"exec","pid":123,...,"package":"requests","label":"benign"}
Line 2: {"type":"open","pid":123,"fname":"/tmp/foo.py",...,"package":"requests","label":"benign"}
Line 3: {"type":"open","pid":123,"fname":"/tmp/bar.py",...,"package":"requests","label":"benign"}
...
Line 2847: {"type":"open","pid":124,"fname":"/tmp/baz.py",...,"package":"requests","label":"benign"}
```

### Per-Package Traces
The `traces/` directories contain individual trace files for each successfully collected package.

Naming convention: `<package>-<version>.jsonl`

Examples:
- `requests-2.28.0.jsonl`
- `numpy-1.24.1.jsonl`
- `datadog__malicious-package-v1.0.jsonl`

### Aggregated JSONL
The `data/` directories contain aggregated event streams:
- `malware.jsonl`: All events from all malicious packages
- `benign.jsonl`: All events from all benign packages

These files are created by merging per-package traces with `scripts/aggregate_jsonl.py`.

## Data Placement Workflow

### Simple: Direct Placement (Recommended)

If you already have the final dataset files:

```bash
# 1. Create structure
make prepare-structure

# 2. Place your dataset files
cp malware.jsonl data/zenodo_13746167/malware/data/
cp benign.jsonl data/zenodo_13746167/benign/data/
cp malware-traces/*.jsonl data/zenodo_13746167/malware/traces/
cp benign-traces/*.jsonl data/zenodo_13746167/benign/traces/

# 3. Validate dataset integrity
make validate-data
# Should output: ✅ DATASET VALIDATION PASSED

# 4. Train model
sudo make train-split
```

### Expected Dataset Format

Your provided files should be:
- `malware.jsonl` - Aggregated malware events (all packages)
- `benign.jsonl` - Aggregated benign events (all packages)
- `*-traces/*.jsonl` - Individual per-package trace files

## Data Validation Rules

### ✅ Valid Data
- Events have required fields
- Event types: exec, open, connect ONLY
- PIDs are positive integers
- Timestamps are positive integers
- Timestamps monotonic within each package
- Package metadata present and consistent

### ❌ Invalid Data
- Missing required fields
- Unknown event types (e.g., "socket", "dns", "http")
- Negative PIDs or timestamps
- Non-monotonic timestamps within package
- Failed installations (should be filtered during collection)
- Empty trace files
- Duplicate package/version traces (indicates collection error)

## Dataset Statistics (Example)

After collection, validation script reports:

```
Malware Dataset
---------------
Packages: 486 (attempted: 500, success rate: 97.2%)
Events: 1,234,567
Avg events/pkg: 2,540
Min/max events: 45 / 12,300
Unique packages: 486
Trace files: 486

Benign Dataset
--------------
Packages: 1,432 (attempted: 1,500, success rate: 95.5%)
Events: 3,456,789
Avg events/pkg: 2,413
Min/max events: 120 / 18,200
Unique packages: 1,432
Trace files: 1,432

Event Type Distribution
-----------------------
exec: 15.2%
open: 82.4%
connect: 2.4%
```

## Important Notes

1. **Do NOT hard-code package counts**
   - The exact number of successful packages is unknown until collection completes
   - Some installations will fail (dependencies, network, etc.)
   - Validation script reports actual counts

2. **Event schema is fixed**
   - Do NOT add new event types
   - Do NOT add network destination fields (dst_ip, dst_port, hostname, etc.)
   - Changes would break ITBG constructor and TGN encoder

3. **Failed installations**
   - Automatically filtered during collection
   - Do NOT appear in final data
   - No manual cleanup needed

4. **Trace file naming**
   - Use sanitized package-version format
   - Handle special characters (/, spaces, etc.)
   - Must be deterministic and unique

5. **Git hygiene**
   - `.jsonl` files in `clean/`, `malicious/`, and `zenodo_13746167/` are gitignored
   - `extracted/` directories are gitignored (large, temporary)
   - `.tmp_traces/` is gitignored
   - Only source code and documentation are committed

## Zenodo Publication

The `data/zenodo_13746167/` directory is structured for Zenodo upload:

```
zenodo_13746167/
├── malware/
│   ├── data/malware.jsonl          # Main dataset
│   └── traces/*.jsonl              # Individual traces (optional)
│
└── benign/
    ├── data/benign.jsonl           # Main dataset
    └── traces/*.jsonl              # Individual traces (optional)
```

Upload to Zenodo using `scripts/prepare_zenodo.py`:
```bash
# Create Zenodo archive
python scripts/prepare_zenodo.py

# Generates: scbf_dataset_zenodo_13746167.tar.gz
# Size: ~100-500 MB (depends on collection)
```

## Dataset Versions

- **v1.0** (Initial): 67 benign + 99 malicious (Datadog)
- **v2.0** (QUT-DV25): +200 packages from QUT-DV25 dataset
- **v3.0** (Target): ~1,500 benign + ~500 malicious (this collection)

## References

- SCBF Architecture: `docs/architecture.md`
- Collection Scripts: `scripts/collect_*.py`
- Validation: `scripts/validate_dataset.py`
- Training: `scbf/training/`
- Event Schema: `scbf/capture/install_monitor.py`

---

**Last Updated**: 2026-09-05
**Contact**: [Maintain separately]
