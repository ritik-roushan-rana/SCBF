# SCBF Monitor Usage Guide

This project uses an improved eBPF-based monitoring system for capturing package installation behavior.

## Monitor Script: `monitor.sh`

The main monitoring script that captures behavioral events during package installation.

### Usage

```bash
sudo ./monitor.sh PACKAGE PYTHON_BIN ARTIFACT OUTPUT
```

### Parameters

- `PACKAGE`: Package name (for logging/metadata)
- `PYTHON_BIN`: Path to Python interpreter to use
- `ARTIFACT`: Path to package artifact (wheel, tar.gz, or directory with setup.py)
- `OUTPUT`: Path to output JSONL file

### Example

```bash
# Monitor requests package installation
sudo ./monitor.sh \
    "requests" \
    "/usr/bin/python3" \
    "requests-2.28.0.tar.gz" \
    "traces/requests-2.28.0.jsonl"
```

### What It Does

1. **Loads eBPF program** - Hooks into kernel syscalls
2. **Tracks process tree** - Monitors pip and all child processes
3. **Captures events** - Records exec, open, connect syscalls
4. **Writes JSONL** - Saves behavioral trace to file

### Events Captured

**exec** - Process execution:
```json
{"type":"exec","pid":123,"ppid":100,"comm":"python3","fname":"/usr/bin/python3","ts":1234567890}
```

**open** - File access:
```json
{"type":"open","pid":123,"ppid":100,"comm":"pip","fname":"/tmp/file.py","ts":1234567891}
```

**connect** - Network connection:
```json
{"type":"connect","pid":123,"ppid":100,"comm":"pip","fname":"connect","ts":1234567892}
```

### Requirements

- Linux kernel 5.x+ with eBPF support
- BCC (BPF Compiler Collection)
- Root privileges (sudo)
- Python 3 with BCC module

### Installation (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```

## Collection Script: `scripts/collect_zenodo.py`

Automated data collection from Zenodo dataset.

### Usage

```bash
python3 scripts/collect_zenodo.py [OPTIONS]
```

### Options

- `--max-artifacts N` - Limit collection to N packages (default: 1500)
- `--skip-malware` - Skip malware collection
- `--skip-benign` - Skip benign collection
- `--output DIR` - Output directory (default: data/zenodo_13746167)

### Example

```bash
# Collect 1000 benign packages
python3 scripts/collect_zenodo.py --max-artifacts 1000 --skip-malware

# Collect both benign and malware (default)
python3 scripts/collect_zenodo.py
```

### What It Does

1. **Extracts packages** from Zenodo ZIP files
2. **Creates virtual environments** per package
3. **Runs monitor.sh** for each package
4. **Saves traces** to `data/zenodo_13746167/*/traces/`
5. **Aggregates** into `malware.jsonl` and `benign.jsonl`
6. **Cleans up** temporary files

### Directory Structure

```
data/zenodo_13746167/
├── malware/
│   ├── traces/          # Individual package traces
│   └── data/
│       └── malware.jsonl  # Aggregated events
└── benign/
    ├── traces/          # Individual package traces
    └── data/
        └── benign.jsonl   # Aggregated events
```

## Improvements Over Old System

### Old System (InstallMonitor)

```python
# Old Python class
from scbf.capture.install_monitor import InstallMonitor

mon = InstallMonitor()
mon.run_and_capture(cmd, duration_sec=60)
```

**Issues:**
- Fragile process tracking
- Missed child processes
- Complex Python/eBPF interaction
- Harder to debug

### New System (monitor.sh)

```bash
# New shell script
sudo ./monitor.sh \
    "requests" \
    "/usr/bin/python3" \
    "requests-2.28.0.tar.gz" \
    "output.jsonl"
```

**Benefits:**
- ✅ Robust process tree tracking
- ✅ Captures all descendant processes
- ✅ Clean separation of concerns
- ✅ Easier to debug and maintain
- ✅ Better event draining
- ✅ Proper root privilege handling

### Key Improvements

1. **Process Tree Tracking**
   - Old: Single PID tracking
   - New: Full process tree with automatic updates

2. **Event Capture**
   - Old: Basic perf buffer
   - New: Larger buffer (128 pages) + loss tracking

3. **eBPF Program**
   - Old: Basic hooks
   - New: Optimized with per-CPU scratch space

4. **Privilege Handling**
   - Old: All-or-nothing root
   - New: Monitor runs as root, pip runs as user

## Migration from Old System

If you have code using the old `InstallMonitor` class:

### Before

```python
from scbf.capture.install_monitor import InstallMonitor

mon = InstallMonitor()
events = []
mon.on_event = lambda e: events.append(e)
mon.run_and_capture(cmd, duration_sec=60)
```

### After

```bash
# Use monitor.sh directly
sudo ./monitor.sh \
    "package-name" \
    "$PYTHON_BIN" \
    "package-artifact.tar.gz" \
    "output.jsonl"

# Or use collect_zenodo.py for automation
python3 scripts/collect_zenodo.py
```

## Troubleshooting

### "Failed to load eBPF"

**Cause:** Kernel doesn't support eBPF or BCC not installed

**Fix:**
```bash
# Check kernel version (need 5.x+)
uname -r

# Install BCC
sudo apt install bpfcc-tools python3-bpfcc
```

### "Monitor must run as root"

**Cause:** eBPF requires root privileges

**Fix:**
```bash
# Always use sudo
sudo ./monitor.sh ...
```

### "No events captured"

**Cause:** Package has no behavioral footprint or process tracking failed

**Fix:**
- Check if pip actually ran
- Verify package was installed
- Check monitor output for errors

### "Permission denied" on output file

**Cause:** Running as root but writing to user directory

**Fix:**
```bash
# Create output directory first
mkdir -p traces/
chmod 777 traces/  # Or chown to your user

# Then run monitor
sudo ./monitor.sh ... "traces/output.jsonl"
```

## Examples

### Monitor Single Package

```bash
#!/bin/bash

PACKAGE="requests"
VERSION="2.28.0"
ARTIFACT="${PACKAGE}-${VERSION}.tar.gz"

# Download artifact
pip download --no-deps "$PACKAGE==$VERSION"

# Monitor installation
sudo ./monitor.sh \
    "$PACKAGE" \
    "/usr/bin/python3" \
    "$ARTIFACT" \
    "traces/${PACKAGE}-${VERSION}.jsonl"

# Check output
wc -l "traces/${PACKAGE}-${VERSION}.jsonl"
head -5 "traces/${PACKAGE}-${VERSION}.jsonl"
```

### Monitor Multiple Packages

```bash
#!/bin/bash

PACKAGES=(
    "requests"
    "click"
    "flask"
)

for pkg in "${PACKAGES[@]}"; do
    echo "Monitoring $pkg..."
    
    # Download
    pip download --no-deps "$pkg"
    
    # Find artifact
    artifact=$(ls ${pkg}*.{tar.gz,whl} 2>/dev/null | head -1)
    
    if [ -z "$artifact" ]; then
        echo "  ❌ No artifact found"
        continue
    fi
    
    # Monitor
    sudo ./monitor.sh \
        "$pkg" \
        "/usr/bin/python3" \
        "$artifact" \
        "traces/${pkg}.jsonl"
    
    echo "  ✓ Done"
done
```

## Performance

**Overhead:** ~5-10% CPU during monitoring  
**Memory:** <100 MB for monitor + eBPF  
**Event rate:** Can handle 10K+ events/second  
**Lost events:** Typically <0.1% with 128-page buffer  

## See Also

- **README.md** - Project overview
- **data/README.md** - Event format specifications
- **docs/TRAINING_DATA_FORMAT.md** - Training data requirements
- **docs/DATASET_READY.md** - Dataset status

---

**For most users:** Use `python3 scripts/collect_zenodo.py` for automated collection.

**For advanced users:** Use `sudo ./monitor.sh` for manual monitoring and custom workflows.
