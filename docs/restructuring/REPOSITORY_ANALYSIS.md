# SCBF Repository Analysis & Restructuring Plan

Generated: 2026-09-05

## 1. Current Repository Structure

```
/Users/shield/Downloads/scbf/
├── scbf/                           # Core Python package ✅
│   ├── capture/                    # eBPF monitoring ✅
│   │   └── install_monitor.py
│   ├── models/                     # TGN + ITBG ✅
│   │   ├── itbg_constructor.py
│   │   └── tgn_encoder.py
│   ├── training/                   # Training pipeline ✅
│   └── detection/                  # CLI scanner ✅
│       └── cli.py
│
├── scripts/                        # Data collection scripts
│   ├── collect_clean_data.py       # ✅ KEEP - clean package collector
│   ├── collect_malicious_data.py   # ✅ KEEP - malicious collector
│   ├── check_distances.py          # ✅ KEEP - analysis tool
│   ├── collect_large_dataset.py    # ⚠️  REMOVE - obsolete orchestrator
│   ├── orchestrate_collection.py   # ⚠️  NOT YET CREATED - use later
│   ├── convert_qutdv25.py          # ⚠️  KEEP - format converter
│   ├── download_qutdv25_full.py    # ⚠️  REMOVE - won't download full 450GB
│   ├── extract_qutdv25_subset.py   # ⚠️  REMOVE - won't use QUT directly
│   ├── inspect_qutdv25.py          # ⚠️  KEEP - inspection tool
│   ├── test_qutdv25_pipeline.py    # ⚠️  KEEP - testing tool
│   └── validate_qutdv25.py         # ⚠️  KEEP - validation tool
│
├── data/                           # ❌ MISSING - needs creation
│   ├── zenodo_13746167/            # Target structure for final dataset
│   │   ├── malware/
│   │   │   ├── data/
│   │   │   │   └── malware.jsonl
│   │   │   ├── traces/
│   │   │   └── extracted/
│   │   └── benign/
│   │       ├── data/
│   │       │   └── benign.jsonl
│   │       ├── traces/
│   │       └── extracted/
│   ├── clean/                      # Legacy clean data location
│   ├── malicious/                  # Legacy malicious data location
│   └── processed/                  # ML-ready processed data
│
├── models/                         # Model checkpoints ✅
│   └── checkpoints/
│
├── tests/                          # Test suite ✅
├── experiments/                    # WIP code ✅
├── docs/                           # Documentation ✅
│
├── Makefile                        # ✅ KEEP - needs update
├── requirements.txt                # ✅ KEEP
├── .gitignore                      # ⚠️  NEEDS UPDATE
└── README.md                       # ✅ KEEP - needs update

```

## 2. Issues Identified

### A. Missing Data Directory Structure
- No `data/` directory exists
- No `data/zenodo_13746167/` structure for final dataset
- No separation of raw vs processed data

### B. Obsolete Scripts
- `collect_large_dataset.py` - Uses SCBF's InstallMonitor, not user's trace.sh
- `download_qutdv25_full.py` - Won't download 450GB dataset
- `extract_qutdv25_subset.py` - Won't use QUT-DV25 directly

### C. Hard-coded Paths
- `collect_malicious_data.py` has hard-coded `/home/ubuntu/` paths
- Assumes Linux environment

### D. Missing Validation Script
- No `scripts/validate_dataset.py` for checking dataset integrity

### E. .gitignore Issues
- References `data/qut_clean/` and `data/qut_malicious/` (temporary/obsolete)
- Doesn't include `data/zenodo_13746167/` structure
- Missing `.tmp_traces/` pattern

### F. Event Schema Compliance
- Current event format: ✅ CORRECT
  - `{"type":"exec","pid":123,"ppid":100,"comm":"python","ts":...}`
  - `{"type":"open","pid":123,"fname":"/path","ts":...}`
  - `{"type":"connect","pid":123,"fname":"connect","ts":...}`
- Monitor adds package metadata (package, version, artifact, label)
- ITBG constructor expects this format

### G. Collector Behavior
- Current collectors (`collect_clean_data.py`, `collect_malicious_data.py`):
  - ✅ Only save if `returncode == 0` AND `events > 0`
  - ✅ Skip failed installations
  - ✅ Write to `data/clean/*.jsonl` or `data/malicious/*.jsonl`
  - ⚠️  Write one file per package (NOT aggregated JSONL yet)

### H. JSONL Design
- Current: One file per package (`requests.jsonl`, `numpy.jsonl`)
- Target: Aggregated event-level JSONL
  - `data/zenodo_13746167/malware/data/malware.jsonl` (all malware events)
  - `data/zenodo_13746167/benign/data/benign.jsonl` (all benign events)
  - Each line = one event with package metadata attached

## 3. Required Changes

### Phase 1: Directory Structure
1. Create `data/zenodo_13746167/` structure
2. Create subdirectories: `malware/{data,traces}`, `benign/{data,traces}`
3. Create `data/clean/` and `data/malicious/` for intermediate files
4. Create `data/processed/` for ML-ready outputs
5. Add `.tmp_traces/` to `.gitignore`

**Note:** We store ONLY behavioral traces (JSONL), not package binaries or extracted files.

### Phase 2: Script Organization
1. **KEEP (No changes needed):**
   - `scripts/collect_clean_data.py` ✅
   - `scripts/collect_malicious_data.py` ✅
   - `scripts/check_distances.py` ✅
   
2. **KEEP (Update paths):**
   - `scripts/convert_qutdv25.py` - Update to use zenodo structure
   - `scripts/inspect_qutdv25.py` - Update docs
   - `scripts/validate_qutdv25.py` - Rename to `validate_dataset.py`
   
3. **ARCHIVE (Move to experiments/):**
   - `scripts/collect_large_dataset.py`
   - `scripts/download_qutdv25_full.py`
   - `scripts/extract_qutdv25_subset.py`
   - `scripts/test_qutdv25_pipeline.py`

4. **CREATE:**
   - `scripts/aggregate_jsonl.py` - Merge per-package files into malware.jsonl/benign.jsonl
   - `scripts/validate_dataset.py` - Comprehensive validation
   - `scripts/prepare_zenodo.py` - Prepare final Zenodo structure

### Phase 3: Event Schema Validation
- ✅ No changes needed - current schema is correct
- ✅ ITBG constructor already handles exec/open/connect events
- ✅ Monitor already adds package metadata

### Phase 4: Gitignore Updates
Add:
```
# Zenodo dataset structure
data/zenodo_13746167/*/extracted/
data/zenodo_13746167/*/traces/*.jsonl
data/zenodo_13746167/*/data/*.jsonl
.tmp_traces/

# Temporary collection files
data/clean/*.jsonl
data/malicious/*.jsonl
data/qut_clean/
data/qut_malicious/
data/collected_clean/
```

### Phase 5: Makefile Updates
Add targets:
- `make prepare-structure` - Create data/ structure
- `make aggregate-data` - Merge per-package JSONL into aggregated files
- `make validate-data` - Run validation checks

### Phase 6: Documentation Updates
Update:
- README.md - Add Zenodo dataset section
- PROJECT_STRUCTURE.md - Document new data/ structure
- Create DATASET_GUIDE.md - How to prepare final dataset

## 4. Validation Requirements

Create `scripts/validate_dataset.py` to check:

### A. File Structure
- [ ] `data/zenodo_13746167/malware/data/malware.jsonl` exists
- [ ] `data/zenodo_13746167/benign/data/benign.jsonl` exists
- [ ] `data/zenodo_13746167/malware/traces/` contains trace files
- [ ] `data/zenodo_13746167/benign/traces/` contains trace files
- [ ] No package binaries or extracted files present

### B. JSONL Format
- [ ] Each line is valid JSON
- [ ] Required fields: `type`, `pid`, `ts`
- [ ] Event types: only `exec`, `open`, `connect`
- [ ] No unexpected fields (no dst_ip, dst_port, hostname)
- [ ] Package metadata present: `package`, `version`, `artifact`, `label`

### C. Data Consistency
- [ ] Number of trace files matches unique package/version combinations
- [ ] No empty trace files
- [ ] No failed installations in final data
- [ ] Events have monotonically increasing timestamps within each package
- [ ] All PIDs are positive integers
- [ ] All timestamps are positive integers

### D. Statistics
Report:
- Total packages (malware/benign)
- Total events (malware/benign)
- Average events per package
- Min/max events per package
- Unique package names
- Unique package versions
- Event type distribution

## 5. Migration Strategy

### Step 1: Create Structure (Non-breaking)
```bash
mkdir -p data/zenodo_13746167/{malware,benign}/{data,traces}
mkdir -p data/{clean,malicious,processed}
mkdir -p data/.tmp_traces
```

**Note:** Only behavioral traces stored, no package binaries.

### Step 2: Archive Obsolete Scripts (Non-breaking)
```bash
mv scripts/collect_large_dataset.py experiments/
mv scripts/download_qutdv25_full.py experiments/
mv scripts/extract_qutdv25_subset.py experiments/
mv scripts/test_qutdv25_pipeline.py experiments/
```

### Step 3: Create New Scripts
- `scripts/aggregate_jsonl.py`
- `scripts/validate_dataset.py`
- `scripts/prepare_zenodo.py`

### Step 4: Update .gitignore
Add Zenodo patterns, .tmp_traces/, etc.

### Step 5: Update Makefile
Add new targets for data preparation

### Step 6: Update Documentation
README.md, PROJECT_STRUCTURE.md

### Step 7: Test Pipeline
```bash
# Collect sample data (existing scripts work)
sudo python scripts/collect_clean_data.py  # Creates data/clean/*.jsonl
sudo python scripts/collect_malicious_data.py  # Creates data/malicious/*.jsonl

# Aggregate into Zenodo format (new script)
python scripts/aggregate_jsonl.py

# Validate (new script)
python scripts/validate_dataset.py

# Train (existing - no changes)
sudo make train-split
```

## 6. Final Dataset Lifecycle

### Collection Phase (User runs on Linux VM)
```
1. Run monitor on 500 malware packages
   → Some succeed, some fail
   → Only successful: data/malicious/*.jsonl (per-package)
   
2. Run monitor on 1500 benign packages
   → Some succeed, some fail
   → Only successful: data/clean/*.jsonl (per-package)
```

### Aggregation Phase (Run locally)
```
3. Aggregate per-package files:
   python scripts/aggregate_jsonl.py
   
   → Reads: data/malicious/*.jsonl
   → Writes: data/zenodo_13746167/malware/data/malware.jsonl
   → Copies traces: data/zenodo_13746167/malware/traces/
   
   → Reads: data/clean/*.jsonl  
   → Writes: data/zenodo_13746167/benign/data/benign.jsonl
   → Copies traces: data/zenodo_13746167/benign/traces/
```

### Validation Phase
```
4. Validate dataset:
   python scripts/validate_dataset.py
   
   → Check structure, format, consistency
   → Report statistics
   → Flag issues
```

### Training Phase
```
5. Train model:
   sudo make train-split
   
   → Reads: data/zenodo_13746167/malware/data/malware.jsonl
   → Reads: data/zenodo_13746167/benign/data/benign.jsonl
   → Writes: models/tgn_v2_best.pt, models/envelope_v2.npy
```

## 7. Key Design Decisions

### A. Trace File Naming
Use: `<package>-<version>.jsonl`
- Sanitize `/` → `-`
- Sanitize spaces → `-`
- Handle version collisions with hash suffix if needed

### B. JSONL Design
Event-level JSONL (one line = one event):
```json
{"type":"exec","pid":123,"ppid":100,"comm":"python","ts":1234567890,"package":"requests","version":"2.28.0","artifact":"requests-2.28.0.tar.gz","label":"benign"}
{"type":"open","pid":123,"fname":"/tmp/site-packages/requests/__init__.py","ts":1234567891,"package":"requests","version":"2.28.0","artifact":"requests-2.28.0.tar.gz","label":"benign"}
```

### C. Failed Installation Handling
- Collector checks: `returncode == 0` AND `len(events) > 0`
- If either fails: skip, don't write file
- No failed packages reach `data/clean/` or `data/malicious/`
- Aggregation script assumes all files are successful

### D. Temporary Files
- Use `data/.tmp_traces/` during collection
- Move to final location only on success
- Add to `.gitignore`

## 8. Testing Plan

### Unit Tests
- [ ] `test_aggregate_jsonl.py` - Test aggregation logic
- [ ] `test_validate_dataset.py` - Test validation checks
- [ ] `test_event_schema.py` - Validate event format

### Integration Tests
- [ ] Collect small sample dataset (3 packages)
- [ ] Aggregate into Zenodo format
- [ ] Validate structure
- [ ] Train model on small dataset
- [ ] Run inference

### Regression Tests
- [ ] Existing pipeline still works
- [ ] ITBG constructor handles events correctly
- [ ] TGN encoder produces valid DNA vectors
- [ ] Envelope comparison works

## 9. Success Criteria

✅ Repository is ready when:
1. `data/zenodo_13746167/` structure exists
2. User can place final `malware.jsonl` and `benign.jsonl` into `data/zenodo_13746167/{malware,benign}/data/`
3. User can place trace files into `data/zenodo_13746167/{malware,benign}/traces/`
4. `make validate-data` passes all checks
5. `make train-split` trains successfully
6. `make scan PKG=requests` produces verdict
7. No hard-coded package counts
8. No fake/synthetic data in repository
9. All obsolete scripts archived
10. Documentation updated

## 10. Next Steps

1. ✅ Create directory structure
2. ✅ Update .gitignore
3. ✅ Archive obsolete scripts
4. ✅ Create aggregate_jsonl.py
5. ✅ Create validate_dataset.py
6. ✅ Create prepare_zenodo.py
7. ✅ Update Makefile
8. ✅ Update README.md
9. ✅ Test pipeline with sample data
10. ✅ Document dataset preparation guide

---

**IMPORTANT NOTES:**

- Do NOT generate fake datasets
- Do NOT modify event schema
- Do NOT assume all installations succeed
- Do NOT hard-code package counts (386 malware, 1500 benign, etc.)
- Keep existing working code intact
- Make minimal, targeted changes
- Prefer structural organization over rewriting

