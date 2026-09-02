# SCBF Architecture

## System Overview

Supply Chain Behavioral Fingerprinting (SCBF) is a kernel-level behavioral detection system for identifying malicious packages during installation. Unlike static analysis or hash-based approaches, SCBF observes *what a package actually does* at install time and compares that behavior against learned models of legitimate installs.

## Core Innovation

**Temporal Graph Networks (TGN) for streaming behavioral encoding**: Traditional graph neural networks require a complete graph before inference. SCBF uses a TGN with persistent memory that updates incrementally with each syscall event, enabling **mid-install verdicts and kill-switch capability** — packages can be terminated before malicious behavior completes.

## Architecture Diagram

```
┌─────────────────┐
│  pip install    │
│     (target)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  eBPF Tracer    │  ◄── Kernel-level syscall hooks
│  (install_      │      (execve, openat, tcp_connect)
│   monitor.py)   │
└────────┬────────┘
         │ Event stream
         ▼
┌─────────────────┐
│ Event Filter &  │  ◄── Remove known-benign noise
│  Normalization  │      (/tmp/pip-*, __pycache__, etc.)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ ITBG Constructor│  ◄── Build heterogeneous temporal graph
│ (itbg_          │      Nodes: processes, files, network
│  constructor.py)│      Edges: exec, open, connect
└────────┬────────┘
         │ Per-event
         ▼
┌─────────────────┐
│  TGN Encoder    │  ◄── Streaming memory-based encoding
│  (tgn_          │      GRU + temporal attention
│   encoder.py)   │      Output: 128-dim "DNA" vector
└────────┬────────┘
         │ DNA vector
         ▼
┌─────────────────┐
│ Envelope        │  ◄── Distance to "normal" centroid
│  Comparison     │      Calibrated thresholds
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Verdict Engine  │  ◄── ALLOW / WARN / BLOCK
│  + Kill-Switch  │      Optional process termination
└─────────────────┘
```

## Component Details

### 1. eBPF Capture (`scbf/capture/install_monitor.py`)

**Purpose**: Kernel-level syscall interception for tamper-resistant monitoring

**Mechanism**:
- Attaches BPF programs to kernel tracepoints:
  - `syscalls:sys_enter_execve` → process spawns
  - `syscalls:sys_enter_openat` → file access
  - `tcp_v4_connect` (future) → network connections
- Filters events by PID ancestry (only track target install process + descendants)
- Emits normalized events to Python userspace via perf buffer

**Output**: JSON event stream
```json
{"type": "exec", "pid": 5722, "ppid": 5720, "comm": "python3", "ts": 166627099800}
{"type": "open", "pid": 5722, "fname": "/etc/ld.so.cache", "ts": 166657638891}
```

**Key Features**:
- Zero code modification to pip/package managers
- Runs outside container/VM boundaries (host-level tracing)
- Sub-millisecond event capture latency

### 2. ITBG Constructor (`scbf/models/itbg_constructor.py`)

**Purpose**: Transform raw syscall events into a typed, temporal graph representation

**Graph Schema**:
- **Nodes**: `proc:{pid}`, `file:{path}`, `net:{ip:port}`
- **Edges**: Typed relations with timestamps and feature vectors
  - `exec`: proc → proc (parent spawns child)
  - `open`: proc → file (process reads/writes file)
  - `connect`: proc → net (process initiates connection)

**Edge Features** (32-dim vector per event):
- Event type encoding (exec=0, open=1, connect=2, ...)
- Path-based flags:
  - `is_credential` (matches /.ssh/, /.aws/, /.env, /etc/passwd)
  - `is_temp` (starts with /tmp, /var/tmp)
  - `is_pip_internal` (/pip-unpack-, /pip-metadata-)
  - `is_site_packages` (contains site-packages or ends in .py/.pyc/.so)
- Path complexity: length, depth (normalized)

**Stage-Aware Snapshotting**:
- Processes the full event stream, but records DNA snapshots at fixed checkpoints (25%, 50%, 75%, 100%)
- Removes dependency on raw event count → addresses length-bias problem

### 3. TGN Encoder (`scbf/models/tgn_encoder.py`)

**Purpose**: Maintain per-node memory and produce a behavioral "DNA" embedding

**Architecture**:

```
TGNMemory:
  ├─ memory: Dict[node_id → 64-dim vector]
  ├─ last_update: Dict[node_id → timestamp]
  ├─ TimeEncode: Learned cosine time encoding
  └─ GRU: Update memory based on messages

Message Function:
  msg = concat(memory[src], edge_features, TimeEncode(Δt))

Update Function:
  memory[dst] ← GRU(msg, memory[dst])

Output Projection:
  DNA = LayerNorm(Linear(memory[dst])) → 128-dim
  DNA ← normalize(DNA)  # Unit length
```

**Key Properties**:
- **Streaming**: Memory updates incrementally, no need to wait for complete graph
- **Temporal**: Time since last update explicitly encoded
- **Persistent**: Memory state carries behavioral context across the event sequence

**Training**:
- Contrastive loss: Pull clean embeddings together, push malicious embeddings away
- Anti-collapse regularization: Prevent trivial constant-output solution
- Early stopping with checkpointing (patience=5 epochs)

### 4. Behavioral Envelope (`scbf/training/build_envelope.py`)

**Purpose**: Define the "normal" behavior manifold for clean packages

**Construction**:
1. Run all clean package captures through trained TGN (inference mode)
2. Collect final DNA vectors: `[v1, v2, ..., vN]`
3. Compute centroid: `c = mean(vectors)`
4. Save as `envelope_v2.npy`

**Thresholds** (calibrated from clean distribution):
```python
mean_dist = 0.0957
std_dist = 0.0286

WARN_threshold = mean + 2*std = 0.1529
BLOCK_threshold = mean + 3*std = 0.1816
```

Any install with distance > BLOCK is flagged as malicious.

### 5. Verdict Engine (`scbf/detection/cli.py`)

**Scoring**:
```python
distance = ||DNA_test - centroid||
if distance > 0.1816:
    verdict = BLOCK
elif distance > 0.1529:
    verdict = WARN
else:
    verdict = ALLOW
```

**Future**: FAISS-based malicious family matching (nearest-neighbor to known malicious DNA vectors)

## Data Flow Example

**Scenario**: User runs `pip install requests`

1. **Capture**: eBPF hooks see:
   - `exec(pip) → exec(python setup.py)`
   - `open(/tmp/pip-install-xyz/requests-2.31.0/setup.py)`
   - `open(/tmp/site-packages/requests/__init__.py)`
   - ... (1600+ events total)

2. **Filter**: Remove noise events (pip staging dirs, pycache)
   - Kept: ~800 meaningful events

3. **Graph Construction**:
   - Node map: `proc:1234`, `file:/tmp/site-packages/requests/__init__.py`, ...
   - Edges with 32-dim features

4. **TGN Encoding** (incremental, per-event):
   - Event 1 → memory update → DNA₁
   - Event 2 → memory update → DNA₂
   - ...
   - Snapshot at 25%, 50%, 75%, 100% → average → final DNA

5. **Verdict**:
   - `||DNA_final - centroid|| = 0.103` (< 0.1529)
   - **ALLOW** — requests is clean

**Malicious example** (hypothetical ctx-style attack):
- Same flow, but includes:
  - `open(~/.aws/credentials)` → `is_credential=1.0` feature
  - `connect(suspicious-ip:443)` → network event
- DNA vector deviates substantially from clean centroid
- Distance > 0.1816 → **BLOCK** + kill process tree

## Known Limitations & Future Work

### Current Limitations

1. **Length correlation** (0.79): Distance still correlates somewhat with install size
   - Mitigation: Stage-aware snapshotting (implemented)
   - Full fix: Per-package-type envelopes (Phase 2)

2. **Small training set**: 60 clean + 99 malicious
   - Target: 10K+ clean, 2K+ malicious for production robustness

3. **Linux-only**: eBPF dependency
   - Windows port: ETW-based capture (Phase 2, deferred)

4. **No network tracing yet**: tcp_connect probe not yet integrated
   - Critical for credential-exfil detection

### Phase 2 Roadmap

- [ ] Expand to 1K+ clean, 500+ malicious samples
- [ ] Package-type classifier (pure-lib vs. native-extension vs. CLI-tool)
- [ ] Per-type, per-stage envelopes
- [ ] Network event capture (tcp_connect, DNS)
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] Mid-install kill-switch with process-tree termination
- [ ] FAISS malicious-family index
- [ ] Explainability layer (report triggering event)

### Phase 3 (Production)

- [ ] Cloud API + SaaS deployment
- [ ] Community threat feed
- [ ] NPM + Cargo ecosystem support
- [ ] SOC2 compliance
- [ ] Real-time telemetry dashboard

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Capture overhead | ~5-10% CPU |
| Memory footprint | <100MB per install |
| Inference latency | <100ms |
| Training time | ~5-10 min (current dataset) |
| Event throughput | ~10K events/sec |

## References

- Original patent disclosure: "Supply Chain Package Behavioral Fingerprinting — TGN Revision"
- TGN paper: "Temporal Graph Networks for Deep Learning on Dynamic Graphs" (Rossi et al.)
- Datadog malicious packages: https://github.com/DataDog/malicious-software-packages-dataset
