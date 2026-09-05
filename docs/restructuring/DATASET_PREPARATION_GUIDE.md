# SCBF Dataset Preparation Guide

This guide explains how to prepare the final SCBF dataset for Zenodo publication and model training.

## Overview

The SCBF dataset collection workflow:
1. **Collection** - Monitor package installations on Linux VM
2. **Aggregation** - Merge per-package traces into Zenodo structure
3. **Validation** - Check dataset integrity
4. **Training** - Train TGN model

## Quick Start

```bash
# 1. Create directory structure
make prepare-structure

# 2. Collect behavioral traces (Linux VM with eBPF)
sudo make collect-data

# 3. Aggregate into Zenodo format
make aggregate-data

# 4. Validate dataset
make validate-data

# 5. Train model
sudo make train-split
```

## Detailed Instructions

### Step 1: Prepare Directory Structure

Create the required directory structure:

```bash
make prepare-structure
```

This creates:
```
data/
├── zenodo_13746167/
│   ├── malware/{data,traces}
│   └── benign/{data,traces}
├── clean/
├── malicious/
├── processed/
└── .tmp_traces/
```

**Important:** Only behavioral traces (JSONL) are stored, NOT package binaries or extracted files.

### Step 2: Collect Behavioral Traces

**Requirements:**
- Linux VM with kernel 5.x+
- eBPF/BCC installed
- Root privileges
- Network access to PyPI

**Collection scripts:**

```bash
# Collect benign packages
sudo python scripts/collect_clean_data.py

# Collect malicious packages (requires Datadog dataset)
sudo python scripts/collect_malicious_data.py
```

**What happens:**
1. Script installs package in isolated sandbox
2. eBPF monitor captures syscalls (exec, open, connect)
3. If installation succeeds AND events captured:
   - Write trace to `data/clean/<package>.jsonl` or `data/malicious/<package>.jsonl`
4. If installation fails OR no events:
   - Skip package (no file created)

**Output:**
- `data/clean/*.jsonl` - Per-package benign traces
- `data/malicious/*.jsonl` - Per-package malicious traces

**Important:**
- Some installations will fail (dependencies, network, etc.) - this is expected
- Only successful collections with events are saved
- Failed packages are automatically skipped
- No manual cleanup needed

### Step 3: Aggregate Data

Merge per-package files into Zenodo structure:

```bash
make aggregate-data
# or
python scripts/aggregate_jsonl.py
```

**What happens:**
1. Reads `data/clean/*.jsonl`
2. Writes aggregated `data/zenodo_13746167/benign/data/benign.jsonl`
3. Copies individual traces to `data/zenodo_13746167/benign/traces/`
4. Repeats for malicious data

**Output:**
```
data/zenodo_13746167/
├── benign/
│   ├── data/benign.jsonl          # All benign events (aggregated)
│   └── traces/*.jsonl              # Individual package traces
└── malware/
    ├── data/malware.jsonl          # All malware events (aggregated)
    └── traces/*.jsonl              # Individual package traces
```

**Important:** Only behavioral traces are stored, not package binaries or malware samples.

**Statistics example:**
```
Benign Dataset
  Processed: 1,432 packages
  Total events: 3,456,789
  Avg events/package: 2,413

Malware Dataset
  Processed: 486 packages
  Total events: 1,234,567
  Avg events/package: 2,540
```

### Step 4: Validate Dataset

Check dataset integrity:

```bash
make validate-data
# or
python scripts/validate_dataset.py
```

**Validation checks:**
- ✅ Directory structure exists
- ✅ JSONL format is valid
- ✅ Required fields present (type, pid, ts)
- ✅ Event types correct (exec, open, connect only)
- ✅ PIDs and timestamps are valid
- ✅ Package metadata present
- ✅ Labels correct (benign/malicious)
- ✅ No unexpected fields (dst_ip, dst_port, etc.)

**Expected output:**
```
VALIDATION SUMMARY

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
  Warnings: 3

✅ DATASET VALIDATION PASSED
```

**If validation fails:**
- Fix errors reported by validator
- Re-run aggregation if needed
- Check collector output for issues

### Step 5: Train Model

Train TGN model on validated dataset:

```bash
sudo make train-split
```

**What happens:**
1. Reads `data/zenodo_13746167/{benign,malware}/data/*.jsonl`
2. Splits into train/val/test sets
3. Trains TGN encoder with contrastive loss
4. Builds behavioral envelope
5. Evaluates on test set

**Output:**
- `models/tgn_v2_best.pt` - Trained TGN model
- `models/envelope_v2.npy` - Behavioral centroid
- `models/checkpoints/*.pt` - Per-epoch checkpoints

**Training time:**
- ~10-20 minutes (depending on dataset size)
- ~5-10% CPU overhead during training

### Step 6: Evaluate Model

Test model performance:

```bash
make evaluate
```

**Metrics:**
- Separation score (clean vs malicious distance)
- False positive rate
- True positive rate
- Threshold calibration

### Step 7: Scan Packages

Use trained model to scan new packages:

```bash
sudo make scan PKG=requests
```

**Verdict:**
- **ALLOW** - Package behavior within normal envelope
- **WARN** - Package behavior suspicious (distance > mean + 2σ)
- **BLOCK** - Package behavior anomalous (distance > mean + 3σ)

## Dataset Format

### Event Schema

Each line in `.jsonl` files represents one behavioral event:

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

### Event Types

- **exec** - Process execution (`execve` syscall)
  - Required: `type`, `pid`, `ppid`, `comm`, `ts`
  
- **open** - File access (`openat` syscall)
  - Required: `type`, `pid`, `fname`, `ts`
  
- **connect** - Network connection (`tcp_connect` probe)
  - Required: `type`, `pid`, `fname` (set to "connect"), `ts`

### Package Metadata

Added by collector:
- `package` - Package name
- `version` - Package version
- `artifact` - Original artifact filename
- `label` - "benign" or "malicious"

## Collection Statistics

Expected collection rates based on experience:

### Benign Packages (PyPI)
- **Attempted:** 1,500 packages
- **Success rate:** 90-95%
- **Expected successful:** 1,350-1,425
- **Avg events/pkg:** 2,000-3,000
- **Total events:** ~2.7-4.3M

### Malicious Packages (Datadog)
- **Attempted:** 500 packages
- **Success rate:** 85-95%
- **Expected successful:** 425-475
- **Avg events/pkg:** 2,000-3,000
- **Total events:** ~0.85-1.4M

### Failure Reasons
- Missing dependencies
- Network timeouts
- Installation errors
- Platform incompatibility (Windows-only packages)
- Build failures (missing compilers, libraries)

**Note:** Failed installations are automatically skipped. Only successful collections with captured events reach the final dataset.

## Dataset Size Estimates

### Disk Space Requirements

**During collection:**
- Per-package traces: ~50-200 KB per package
- Temporary files: ~100-500 MB total
- Total: ~1-2 GB

**After aggregation:**
- Aggregated JSONL: ~200-500 MB
- Individual traces: ~100-300 MB
- Compressed archive: ~50-150 MB

**For training:**
- Processed tensors: ~500 MB-1 GB
- Model checkpoints: ~50-100 MB
- Total: ~1-2 GB

## Troubleshooting

### "No events captured" warnings

**Causes:**
- Package has no behavioral footprint (metadata-only)
- eBPF monitor not running
- Permission issues

**Solutions:**
- Check `sudo` privileges
- Verify BCC installed: `dpkg -l | grep bpfcc-tools`
- Check kernel version: `uname -r` (need 5.x+)

### JSON validation errors

**Causes:**
- Corrupted trace files
- Encoding issues
- Partial writes

**Solutions:**
- Re-run collection for affected packages
- Check disk space
- Validate individual files: `jq . < file.jsonl`

### Installation failures

**Causes:**
- Missing system dependencies
- Network issues
- Package incompatibility

**Solutions:**
- Install missing dependencies: `apt install build-essential python3-dev`
- Check network access to PyPI
- Skip incompatible packages (automatic)

### Memory issues during training

**Causes:**
- Large dataset
- Insufficient RAM

**Solutions:**
- Reduce batch size in training config
- Use smaller subset for testing
- Increase swap space

## Advanced Usage

### Custom Package Lists

Edit package lists in collection scripts:

```python
# scripts/collect_clean_data.py
PACKAGES = [
    "your-package-1",
    "your-package-2",
    # ...
]
```

### Collection Limits

Adjust collection limits:

```python
# scripts/collect_malicious_data.py
MAX_SAMPLES = 500  # Limit malicious samples
```

### Timeout Settings

Adjust per-package timeout:

```python
# In collection scripts
mon.run_and_capture(cmd, duration_sec=120)  # 2 minutes
```

### Resume Interrupted Collection

Collections can be resumed - existing files are preserved:

```bash
# Re-run collection (skips existing files)
sudo python scripts/collect_clean_data.py
```

## Next Steps

After preparing dataset:

1. **Publish to Zenodo**
   - Create archive: `tar -czf scbf_dataset.tar.gz data/zenodo_13746167/`
   - Upload to Zenodo
   - Get DOI

2. **Share with Community**
   - Add DOI to README
   - Document collection methodology
   - Provide citation instructions

3. **Expand Dataset**
   - Collect more packages
   - Add new malicious samples
   - Re-train with larger dataset

## References

- [Data Format Documentation](data/README.md)
- [Repository Analysis](REPOSITORY_ANALYSIS.md)
- [Architecture Documentation](docs/architecture.md)
- [Training Guide](TRAINING_GUIDE.md)

## Contact

For questions about dataset preparation:
- Open GitHub issue
- Check documentation
- Review existing issues

---

**Last Updated:** 2026-09-05
