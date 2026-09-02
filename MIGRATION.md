# Migration Guide - Old Structure → New Structure

## Overview

This document maps the old flat structure to the new organized package structure.

## File Mapping

### Core Code Files

| Old Location | New Location | Purpose |
|--------------|--------------|---------|
| `install_monitor.py` | `scbf/capture/install_monitor.py` | eBPF event capture |
| `tgn_encoder.py` | `scbf/models/tgn_encoder.py` | TGN encoder + memory |
| `itbg_constructor.py` | `scbf/models/itbg_constructor.py` | Graph construction |
| `train_v2.py` | `scbf/training/train.py` | Model training |
| `build_envelope_v2.py` | `scbf/training/build_envelope.py` | Envelope builder |
| `cli.py` | `scbf/detection/cli.py` | CLI scanner |

### Utility Scripts

| Old Location | New Location | Purpose |
|--------------|--------------|---------|
| `collect_dataset.py` | `scripts/collect_clean_data.py` | Clean data collection |
| `capture_datadog_samples.py` | `scripts/collect_malicious_data.py` | Malicious data collection |
| `check_distances.py` | `scripts/check_distances.py` | Distance analysis |

### Test Files

| Old Location | New Location | Purpose |
|--------------|--------------|---------|
| `test_tgn.py` | `tests/test_tgn.py` | TGN unit test |
| `test_pipeline.py` | `tests/test_pipeline.py` | Pipeline integration test |
| `debug_replay.py` | `tests/debug_replay.py` | Replay debugger |

### Experimental/Deprecated

| Old Location | New Location | Status |
|--------------|--------------|--------|
| `capture_v1.py` | `experiments/` | Early prototype |
| `capture_v2.py` | `experiments/` | Iterative version |
| `build_envelope.py` | `experiments/` | v1, superseded by v2 |
| `train_debug.py` | `experiments/` | Debug version |

### Data

| Old Location | New Location | Notes |
|--------------|--------------|-------|
| `data/clean/*.jsonl` | `data/clean/` | Keep as-is |
| `data/malicious/*.jsonl` | `data/malicious/` | Keep as-is |
| `data/data/clean/` | *DELETE* | Duplicate/stale data |

### Model Artifacts

| Old Location | New Location | Notes |
|--------------|--------------|-------|
| `tgn_v1.pt` | `models/` (archived) | Phase 1 model |
| `tgn_v2.pt` | `models/tgn_v2_best.pt` | Current best |
| `envelope_pure_python.npy` | `models/` (archived) | Phase 1 envelope |
| `envelope_v2.npy` | `models/envelope_v2.npy` | Current envelope |

## Import Changes

### Old imports:
```python
from tgn_encoder import TGNEncoder
from itbg_constructor import ITBGConstructor
from install_monitor import InstallMonitor
```

### New imports:
```python
from scbf.models.tgn_encoder import TGNEncoder
from scbf.models.itbg_constructor import ITBGConstructor
from scbf.capture.install_monitor import InstallMonitor

# Or shorter:
from scbf import TGNEncoder, ITBGConstructor
from scbf.capture import InstallMonitor
```

## Command Changes

### Old commands:
```bash
sudo python3 train_v2.py
sudo python3 build_envelope_v2.py
sudo python3 cli.py --package requests
sudo python3 collect_dataset.py
```

### New commands:
```bash
sudo python -m scbf.training.train
sudo python -m scbf.training.build_envelope
sudo python -m scbf.detection.cli --package requests
sudo python scripts/collect_clean_data.py

# Or with Makefile:
sudo make train
sudo make scan PKG=requests
sudo make collect-data
```

## Path Updates Required

If you have existing scripts referencing old paths, update as follows:

### In Python files:

**Old:**
```python
clean_paths = glob.glob("data/clean/*.jsonl")
model.load_state_dict(torch.load("tgn_v2.pt"))
centroid = np.load("envelope_v2.npy")
```

**New:**
```python
clean_paths = glob.glob("data/clean/*.jsonl")  # Same
model.load_state_dict(torch.load("models/tgn_v2_best.pt"))
centroid = np.load("models/envelope_v2.npy")
```

### In shell scripts:

**Old:**
```bash
python3 cli.py --package $PKG
```

**New:**
```bash
python -m scbf.detection.cli --package $PKG
```

## Migration Checklist

- [x] Create new directory structure
- [x] Copy core code files to proper locations
- [x] Create `__init__.py` files for proper Python package
- [x] Create documentation (README, QUICKSTART, architecture)
- [x] Create `setup.py` for installable package
- [x] Create `.gitignore` for clean repo
- [x] Add `requirements.txt`
- [x] Add `Makefile` for common tasks
- [ ] **Manual Step**: Copy your actual data files
- [ ] **Manual Step**: Copy your trained models
- [ ] **Manual Step**: Test imports work
- [ ] **Manual Step**: Run full workflow to verify

## Manual Steps to Complete

### 1. Copy Your Data

```bash
# From old directory
cp -r /Users/shield/Downloads/final/data/clean/*.jsonl \
      /Users/shield/Downloads/scbf_structured/data/clean/

cp -r /Users/shield/Downloads/final/data/malicious/*.jsonl \
      /Users/shield/Downloads/scbf_structured/data/malicious/
```

### 2. Copy Your Models (if trained)

```bash
# If you have trained models
cp /Users/shield/Downloads/final/tgn_v2_best.pt \
   /Users/shield/Downloads/scbf_structured/models/

cp /Users/shield/Downloads/final/envelope_v2.npy \
   /Users/shield/Downloads/scbf_structured/models/
```

### 3. Test Installation

```bash
cd /Users/shield/Downloads/scbf_structured
pip install -e .

# Verify imports work
python -c "from scbf import TGNEncoder; print('OK')"
```

### 4. Run a Quick Test

```bash
# If you have models and data already:
sudo python -m scbf.detection.cli --package requests

# Or start fresh:
sudo make collect-data  # Will take time
sudo make train
sudo make scan PKG=requests
```

## Benefits of New Structure

✅ **Proper Python package**: Can install with `pip install -e .`  
✅ **Clean imports**: `from scbf import TGNEncoder` instead of relative imports  
✅ **Separation of concerns**: capture/models/training/detection clearly separated  
✅ **Documentation**: README, QUICKSTART, architecture docs in one place  
✅ **Version control ready**: `.gitignore` configured properly  
✅ **Scripts separated**: Utility scripts in `scripts/`, tests in `tests/`  
✅ **Makefile**: Common tasks (`make train`, `make scan`) simplified  
✅ **Professional**: Ready for GitHub, collaboration, or productionization  

## Keeping the Old Directory

The old `/Users/shield/Downloads/final/` directory is **preserved** — nothing was deleted.

You can:
- Keep both for now (compare side-by-side)
- Archive the old one once new structure validated
- Delete old one after confirming everything works

Recommended:
```bash
# After verifying new structure works
mv /Users/shield/Downloads/final /Users/shield/Downloads/final_backup_$(date +%Y%m%d)
```
