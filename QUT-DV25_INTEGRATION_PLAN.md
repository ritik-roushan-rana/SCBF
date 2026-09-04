# QUT-DV25 Dataset Integration Plan

## Executive Summary

This document outlines the integration of the QUT-DV25 dataset into the existing SCBF (Supply Chain Behavioral Fingerprinting) pipeline WITHOUT modifying the core TGN/ITBG architecture.

---

## Phase 1: Understanding - COMPLETE ✅

### 1.1 SCBF Existing Event Format

**Current SCBF expects events in JSONL format:**

```json
{"type": "exec", "pid": 11548, "ppid": 11536, "comm": "python3", "ts": 14789979651140}
{"type": "open", "pid": 11548, "fname": "/etc/ld.so.cache", "ts": 14789981043246}
```

**Required fields per event type:**

**exec events:**
- `type`: "exec"
- `pid`: process ID (integer)
- `ppid`: parent process ID (integer)
- `comm`: command/process name (string)
- `ts`: timestamp in nanoseconds (integer)

**open events:**
- `type`: "open"
- `pid`: process ID (integer)
- `fname`: file path (string)
- `ts`: timestamp in nanoseconds (integer)

**connect events (optional):**
- `type`: "connect"
- `pid`: process ID (integer)
- Additional network fields
- `ts`: timestamp in nanoseconds (integer)

### 1.2 SCBF Pipeline Flow

```
JSONL Events → ITBGConstructor.add_event() → TGNEncoder.step() → DNA embedding
```

**Key constraints:**
1. Events MUST be sorted by timestamp
2. Noise filtering happens in ITBGConstructor
3. Stage-aware replay uses 25/50/75/100% snapshots
4. Label (0=clean, 1=malicious) determined by directory structure

### 1.3 QUT-DV25 Dataset Structure

**Location:** `/Users/shield/Downloads/scbf/QUT-DV25_Datasets/`

**Structure:**
```
QUT-DV25_Datasets/
├── QUT-DV_Raw_Datasets/
│   ├── QUT-DV25_Benign_Raw_Data_Samples/     (200 benign packages)
│   │   ├── QUT-DV25_Filetop_Traces/
│   │   ├── QUT-DV25_Installation_Traces/
│   │   ├── QUT-DV25_Opensnoop_Traces/        (file open events)
│   │   ├── QUT-DV25_PIDs/                    (single PID per package)
│   │   ├── QUT-DV25_Pattern_Traces/
│   │   └── QUT-DV25_TCP_Traces/
│   │
│   └── QUT-DV25_Malicious_Raw_Data_Samples/  (200 malicious packages)
│       ├── QUT-DV25_Filetop_Traces/
│       ├── QUT-DV25_Installation_Traces/
│       ├── QUT-DV25_Opensnoop_Traces/
│       ├── QUT-DV25_PIDs/
│       ├── QUT-DV25_Pattern_Traces/
│       └── QUT-DV25_TCP_Traces/
│
└── QUT-DV25_Processed_Datasets/
    ├── QUT-DV25_Filetop_Traces/
    │   └── QUT-DV25_Filetop_Traces.csv       (aggregate statistics)
    ├── QUT-DV25_Install_Traces/
    ├── QUT-DV25_Opensnoop_Traces/
    ├── QUT-DV25_Pattern_Traces/
    ├── QUT-DV25_SysCall_Traces/
    └── QUT-DV25_TCP_Traces/
```

**Dataset size:**
- ~14,271 total packages in processed CSV
- 200 benign raw samples
- 200 malicious raw samples  
- Level 0 = benign, Level 1 = malicious

**Available raw traces:**
- `*_opensnoop_trace.txt`: File open events (PID, COMM, FD, ERR, PATH)
- `*_PIDs/*.txt`: Single root PID per package
- `*_installation_trace.txt`: pip install output
- TCP, Filetop, Pattern traces also available

### 1.4 Mapping Strategy

**QUT-DV25 → SCBF Event Mapping:**

| QUT-DV25 Source | SCBF Event Type | Mapping |
|-----------------|-----------------|---------|
| Opensnoop trace | `open` | PID + PATH → {type:"open", pid, fname, ts} |
| Root PID | `exec` | Create synthetic root exec event |
| (No exec traces) | N/A | Synthesize parent-child from context |
| TCP traces | `connect` | (Future: if needed) |

**Challenge:** QUT-DV25 lacks explicit process execution (exec) traces.

**Solution:** 
1. Use opensnoop (file operations) as primary data source
2. Create synthetic root `exec` event using PID from PIDs file
3. Assign timestamps based on event order (monotonic increment)

---

## Phase 2: Converter Design

### 2.1 Conversion Pipeline

```
QUT-DV25 Raw Traces
    ↓
Parse opensnoop trace
    ↓
Extract PID from PIDs file
    ↓
Generate synthetic timestamps
    ↓
Create SCBF-format JSONL
    ↓
Validate event format
    ↓
Save to data/qut_clean/ or data/qut_malicious/
```

### 2.2 Timestamp Generation

**Problem:** QUT-DV25 opensnoop traces lack timestamps.

**Solution:**
```python
BASE_TS = 1000000000000  # Arbitrary base timestamp
ts_current = BASE_TS
ts_increment = 1000000  # 1ms between events

for event in opensnoop_events:
    event['ts'] = ts_current
    ts_current += ts_increment
```

This preserves temporal ordering while fitting SCBF's nanosecond format.

### 2.3 Process Hierarchy

**Problem:** No explicit parent-child process relationships.

**Solution:**
- Use single root PID from PIDs file
- All events share same PID
- Create one synthetic root exec event: `{type:"exec", pid:ROOT_PID, ppid:0, comm:"pip", ts:BASE_TS}`
- All file opens reference same PID

### 2.4 Event Format Conversion

**Opensnoop line format:**
```
24584  pip    3   0 /home/Tanzir/Analysis/Environments/1337x_env/lib/python3.12/site-packages/pip/_vendor/idna/idnadata.py
```

**Fields:**
- Column 1: PID
- Column 2: COMM (command name)
- Column 3: FD (file descriptor)
- Column 4: ERR (error code)
- Column 5+: PATH (file path)

**SCBF open event:**
```json
{"type": "open", "pid": 24584, "fname": "/home/Tanzir/.../idnadata.py", "ts": 1000001000000}
```

### 2.5 Label Assignment

**Level column in CSV:**
- Level 0 = Benign → save to `data/qut_clean/`
- Level 1 = Malicious → save to `data/qut_malicious/`

**Package name from filename:**
- `1337x_opensnoop_trace.txt` → `1337x.jsonl`

---

## Phase 3: Implementation Scripts

### 3.1 Converter Script: `scripts/convert_qutdv25.py`

**Features:**
- Stream processing (no full dataset in RAM)
- Parse opensnoop traces line-by-line
- Generate SCBF-format JSONL
- Validate required fields
- Handle errors gracefully
- Progress reporting

**Output:**
```
data/
├── qut_clean/
│   ├── 1337x.jsonl
│   ├── Acquisition.jsonl
│   ├── ...
│
└── qut_malicious/
    ├── aaiohttp.jsonl
    ├── aihottp.jsonl
    └── ...
```

### 3.2 Validation Script: `scripts/validate_qutdv25.py`

**Checks:**
1. JSON syntax
2. JSONL structure (one event per line)
3. Required fields present
4. Field types correct
5. Timestamp ordering
6. No duplicate events
7. Non-empty samples

**Output:**
```
Total clean samples: 200
Total malicious samples: 200

Valid clean samples: 198
Valid malicious samples: 195

Invalid samples: 7

Average events/sample: 1842
Minimum events/sample: 245
Maximum events/sample: 8045
```

### 3.3 Integration Test: `scripts/test_qutdv25_pipeline.py`

**Tests:**
```python
# Load converted sample
events = load_events("data/qut_clean/1337x.jsonl")

# Feed to ITBG
constructor = ITBGConstructor(tgn_encoder)
dna = constructor.replay_session(events)

# Verify DNA generated
assert dna is not None
assert dna.shape == expected_shape
```

### 3.4 Updated Training: Merge QUT-DV25 with existing data

**Modify `scbf/training/train_with_split.py`:**

```python
# Original data
clean_paths_orig = glob.glob("data/clean/*.jsonl")
mal_paths_orig = glob.glob("data/malicious/*.jsonl")

# QUT-DV25 data
clean_paths_qut = glob.glob("data/qut_clean/*.jsonl")
mal_paths_qut = glob.glob("data/qut_malicious/*.jsonl")

# Combine
clean_paths = clean_paths_orig + clean_paths_qut
mal_paths = mal_paths_orig + mal_paths_qut
```

---

## Phase 4: Data Organization

### 4.1 Final Directory Structure

```
SCBF/
├── data/
│   ├── clean/                     # Original SCBF BPF captures (67 packages)
│   │   ├── requests.jsonl
│   │   └── ...
│   │
│   ├── malicious/                 # Original SCBF Datadog dataset (99 packages)
│   │   └── ...
│   │
│   ├── qut_clean/                 # ⭐ NEW: QUT-DV25 benign (200 packages)
│   │   ├── 1337x.jsonl
│   │   └── ...
│   │
│   └── qut_malicious/             # ⭐ NEW: QUT-DV25 malicious (200 packages)
│       ├── aaiohttp.jsonl
│       └── ...
│
├── QUT-DV25_Datasets/            # Original QUT-DV25 (read-only)
│   └── ...                        # DO NOT MODIFY
│
└── scbf/                          # Existing SCBF code (minimal changes)
    ├── capture/
    ├── models/
    └── training/
```

### 4.2 Dataset Statistics

**After conversion:**

| Source | Type | Count | Total |
|--------|------|-------|-------|
| Original SCBF BPF | Clean | 67 | 166 |
| Original SCBF Datadog | Malicious | 99 | |
| QUT-DV25 | Clean | ~200 | 400 |
| QUT-DV25 | Malicious | ~200 | |
| **TOTAL** | | | **~566 packages** |

**Training split (70/15/15):**
- Train: ~396 packages
- Validation: ~85 packages
- Test: ~85 packages

---

## Phase 5: Compatibility Verification

### 5.1 No Breaking Changes

**What stays the same:**
✅ TGNEncoder architecture
✅ ITBGConstructor logic
✅ Noise filtering patterns
✅ Stage-aware replay
✅ Training loop
✅ Loss function
✅ Model checkpoint format
✅ Evaluation metrics

**What changes:**
- Add QUT-DV25 converter scripts (new files)
- Update data loader to include `qut_clean/` and `qut_malicious/`
- Documentation updates

### 5.2 Event Format Compatibility

**SCBF expected:**
```json
{"type": "open", "pid": 11548, "fname": "/path", "ts": 14789979651140}
```

**QUT-DV25 converted:**
```json
{"type": "open", "pid": 24584, "fname": "/home/.../file.py", "ts": 1000001000000}
```

✅ All required fields present
✅ Correct types
✅ Temporal ordering preserved
✅ Compatible with ITBGConstructor

### 5.3 Known Limitations

1. **No real exec events:** QUT-DV25 lacks process execution traces
   - Impact: Cannot model fork/spawn patterns
   - Mitigation: Synthetic root exec event + all opens share same PID

2. **Synthetic timestamps:** Generated, not real kernel timestamps
   - Impact: Timestamp values are relative, not absolute
   - Mitigation: Temporal ORDER preserved, which is what TGN uses

3. **Limited process hierarchy:** Single PID per package
   - Impact: Cannot model multi-process malware
   - Mitigation: Focus on file access patterns (primary signal)

4. **Different trace source:** eBPF vs. opensnoop
   - Impact: Event coverage may differ
   - Mitigation: Both capture file operations (core behavior)

**These limitations are acceptable** because:
- TGN focuses on temporal file access patterns
- ITBG already handles single-process flows
- Synthetic timestamps preserve event ORDER
- We're augmenting, not replacing, original data

---

## Phase 6: Implementation Checklist

### 6.1 Script Creation
- [ ] `scripts/inspect_qutdv25.py` - Dataset inspector
- [ ] `scripts/convert_qutdv25.py` - Main converter
- [ ] `scripts/validate_qutdv25.py` - Validation
- [ ] `scripts/test_qutdv25_pipeline.py` - Integration test

### 6.2 Converter Features
- [ ] Stream processing (low memory)
- [ ] Progress bar
- [ ] Error handling
- [ ] Skip invalid samples
- [ ] Log statistics
- [ ] Dry-run mode

### 6.3 Validation
- [ ] Test on 5 sample packages first
- [ ] Verify JSONL format
- [ ] Check timestamp ordering
- [ ] Validate through ITBG
- [ ] Generate test DNA embeddings
- [ ] Compare with original SCBF samples

### 6.4 Integration
- [ ] Update training data loader
- [ ] Test train/val/test split with merged data
- [ ] Verify no data leakage
- [ ] Run small training test
- [ ] Compare loss curves

### 6.5 Documentation
- [ ] Update README
- [ ] Add QUT-DV25 section to TRAINING_GUIDE
- [ ] Document converter usage
- [ ] Add troubleshooting guide

---

## Phase 7: Usage

### 7.1 Converter Usage

```bash
# Inspect dataset
python scripts/inspect_qutdv25.py

# Convert (dry run)
python scripts/convert_qutdv25.py --dry-run

# Convert for real
python scripts/convert_qutdv25.py \
    --input QUT-DV25_Datasets/QUT-DV_Raw_Datasets \
    --output data

# Validate
python scripts/validate_qutdv25.py

# Test integration
python scripts/test_qutdv25_pipeline.py
```

### 7.2 Training with Merged Dataset

```bash
# Train with both original + QUT-DV25
sudo make train-split

# Evaluate
sudo make evaluate
```

### 7.3 Expected Improvements

**With 400+ additional packages:**
- Better generalization
- Lower test error
- More robust feature learning
- Better class separation
- Higher F1 score

---

## Phase 8: Risks and Mitigations

### 8.1 Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Incompatible event format | High | Low | Thorough validation, test pipeline |
| Data quality issues | Medium | Medium | Validation script, manual inspection |
| Label noise (wrong labels) | High | Low | Cross-reference with CSV Level column |
| Timestamp issues | Medium | Low | Validate monotonic ordering |
| OOM during conversion | Medium | Low | Stream processing, chunked reads |
| Train/test leakage | Critical | Low | Package-level splitting |

### 8.2 Rollback Plan

If integration fails:
1. Keep QUT-DV25 data separate (`qut_clean/`, `qut_malicious/`)
2. Training can ignore QUT dirs and use only `clean/` and `malicious/`
3. No changes to core SCBF code → instant rollback
4. Original 166-package dataset still works

---

## Phase 9: Success Criteria

### 9.1 Conversion Success
✅ All 400 packages converted without errors
✅ Valid JSONL format
✅ Timestamps monotonically increasing
✅ Required fields present
✅ No corrupted files

### 9.2 Integration Success
✅ Training runs without errors
✅ DNA embeddings generated for QUT samples
✅ No performance degradation
✅ Model converges normally
✅ Test accuracy ≥ baseline

### 9.3 Quality Metrics
- Clean samples pass through ITBG: >95%
- Malicious samples pass through ITBG: >95%
- Average events/sample: 500-5000
- Test F1 score: ≥0.85 (target)

---

## Phase 10: Timeline

| Phase | Task | Duration | Status |
|-------|------|----------|--------|
| 1 | Inspection & Analysis | 2 hours | ✅ COMPLETE |
| 2 | Script implementation | 3 hours | ⏳ Next |
| 3 | Small-scale test (5 samples) | 1 hour | |
| 4 | Full conversion (400 samples) | 1 hour | |
| 5 | Validation | 1 hour | |
| 6 | Integration test | 1 hour | |
| 7 | Training test | 2 hours | |
| 8 | Documentation | 1 hour | |

**Total estimated time:** ~12 hours

---

## Summary

**Goal:** Integrate QUT-DV25 dataset into SCBF without changing TGN architecture.

**Approach:** Convert QUT-DV25 opensnoop traces into SCBF-compatible JSONL format.

**Status:** Analysis complete, ready for implementation.

**Next steps:**
1. Implement converter script
2. Test on 5 samples
3. Full conversion
4. Validate and integrate
5. Train and evaluate

**Impact:** 3x more training data (166 → 566 packages), better model generalization.

