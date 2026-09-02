SCBF - Supply Chain Behavioral Fingerprinting
Project Structure Overview
================================================================================

scbf_structured/
│
├── README.md                       # Main project documentation
├── QUICKSTART.md                   # Step-by-step setup guide
├── MIGRATION.md                    # Old → new structure mapping
├── PROJECT_STRUCTURE.txt          # This file
├── requirements.txt                # Python dependencies
├── setup.py                        # Package installation
├── Makefile                        # Common task shortcuts
├── .gitignore                      # Git ignore rules
│
├── scbf/                          # Main Python package
│   ├── __init__.py                # Package exports
│   │
│   ├── capture/                   # eBPF event capture
│   │   ├── __init__.py
│   │   └── install_monitor.py    # Kernel-level syscall tracer
│   │
│   ├── models/                    # TGN encoder & graph construction
│   │   ├── __init__.py
│   │   ├── tgn_encoder.py        # Temporal Graph Network
│   │   └── itbg_constructor.py   # Behavioral graph builder
│   │
│   ├── training/                  # Model training & envelope
│   │   ├── __init__.py
│   │   ├── train.py              # Contrastive loss training
│   │   └── build_envelope.py     # Behavioral centroid builder
│   │
│   └── detection/                 # CLI detector & verdict engine
│       ├── __init__.py
│       └── cli.py                # Command-line scanner
│
├── scripts/                       # Data collection utilities
│   ├── collect_clean_data.py     # Clean package captures
│   ├── collect_malicious_data.py # Malicious sample captures
│   └── check_distances.py        # Distance analysis tool
│
├── tests/                         # Test suite
│   ├── test_tgn.py               # TGN unit tests
│   ├── test_pipeline.py          # Integration tests
│   └── debug_replay.py           # Debug replay tool
│
├── data/                          # Training data storage
│   ├── README.md                 # Data format documentation
│   ├── clean/                    # Legitimate package captures
│   │   └── *.jsonl               # One file per package
│   └── malicious/                # Malicious package captures
│       └── *.jsonl               # One file per malicious sample
│
├── models/                        # Saved model weights
│   ├── tgn_v2_best.pt           # Best trained model
│   ├── envelope_v2.npy          # Behavioral centroid
│   └── checkpoints/             # Per-epoch checkpoints
│       ├── tgn_epoch0.pt
│       ├── tgn_epoch1.pt
│       └── ...
│
├── experiments/                   # Experimental/WIP code
│   ├── capture_v2.py             # Early capture versions
│   ├── build_envelope.py         # v1 envelope (archived)
│   └── train_debug.py            # Debug training script
│
└── docs/                          # Documentation
    └── architecture.md            # System architecture deep-dive

================================================================================
Key Components
================================================================================

1. eBPF Capture (scbf/capture/)
   - Kernel-level syscall interception (execve, openat, tcp_connect)
   - PID-scoped event filtering
   - Zero-overhead perf buffer streaming
   - Requires: Linux 5.x+, root access, BCC installed

2. TGN Encoder (scbf/models/tgn_encoder.py)
   - Temporal Graph Network with persistent node memory
   - GRU-based memory updates + temporal attention
   - 128-dimensional behavioral "DNA" output
   - Stage-aware snapshotting (25%, 50%, 75%, 100%)

3. ITBG Constructor (scbf/models/itbg_constructor.py)
   - Heterogeneous graph: proc/file/net nodes
   - 32-dim edge features (type, credential flags, path stats)
   - Noise filtering (pip internals, __pycache__)
   - Node ID mapping and deduplication

4. Training Pipeline (scbf/training/)
   - Contrastive loss: clean together, malicious apart
   - Early stopping (patience=5 epochs)
   - Checkpointing + best-model tracking
   - Anti-collapse regularization

5. Behavioral Envelope (scbf/training/build_envelope.py)
   - Centroid of clean package DNA vectors
   - Calibrated thresholds (mean + 2σ, mean + 3σ)
   - Distance-based anomaly scoring

6. CLI Detector (scbf/detection/cli.py)
   - Real-time verdict: ALLOW / WARN / BLOCK
   - Captures install-time events
   - Distance to envelope → threat score
   - Future: mid-install kill-switch

================================================================================
Typical Workflow
================================================================================

1. Setup (one-time):
   sudo apt install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
   cd scbf_structured
   pip install -e .

2. Collect Data (~30 min):
   sudo python scripts/collect_clean_data.py
   sudo python scripts/collect_malicious_data.py

3. Train Model (~10 min):
   sudo python -m scbf.training.train
   sudo python -m scbf.training.build_envelope

4. Scan Packages:
   sudo python -m scbf.detection.cli --package requests
   
   Or with Makefile:
   sudo make scan PKG=requests

================================================================================
File Formats
================================================================================

Event Stream (.jsonl):
  {"type": "exec", "pid": 1234, "ppid": 1233, "comm": "python3", "ts": 166627099800}
  {"type": "open", "pid": 1234, "fname": "/tmp/site-packages/foo.py", "ts": 166657638891}

Model Files:
  tgn_v2_best.pt       PyTorch state_dict (~15MB)
  envelope_v2.npy      NumPy array, 128-dim float32 (~512 bytes)

Checkpoints:
  tgn_epoch{N}.pt      Per-epoch snapshots for analysis/recovery

================================================================================
Performance Metrics
================================================================================

Capture:     ~5-10% CPU overhead, <100MB memory
Inference:   <100ms per verdict
Training:    ~5-10 min (60 clean + 99 malicious)
Event rate:  ~10K events/sec throughput

================================================================================
Current Dataset
================================================================================

Clean packages:    60+ (requests, numpy, django, pandas, flask, ...)
Malicious samples: 99 (Datadog confirmed malicious packages)
Avg events/pkg:    ~2000-4000 events
Total data size:   ~50-100MB compressed

================================================================================
Known Limitations
================================================================================

1. Length correlation (0.79) - distance correlates with install size
   → Mitigation: stage-aware snapshotting (implemented)
   → Full fix: per-type envelopes (Phase 2)

2. Small training set - production needs 10K+ clean, 2K+ malicious

3. Linux-only - eBPF dependency (Windows port deferred to Phase 2)

4. No network capture yet - tcp_connect probe not integrated

================================================================================
Next Steps (Phase 2)
================================================================================

□ Expand to 1K+ clean, 500+ malicious samples
□ Package-type classifier (pure-lib vs native-extension)
□ Per-type, per-stage behavioral envelopes
□ Network event capture (tcp_connect, DNS)
□ CI/CD integration (GitHub Actions, GitLab CI)
□ Mid-install kill-switch with process termination
□ FAISS malicious-family index (nearest-neighbor)
□ Explainability layer (report triggering event)

================================================================================
Documentation
================================================================================

README.md            High-level overview, installation, features
QUICKSTART.md        Step-by-step first-run guide
MIGRATION.md         Old structure → new structure mapping
docs/architecture.md Deep technical architecture
data/README.md       Data format specifications

================================================================================
For More Information
================================================================================

- Original patent disclosure: "Supply Chain Package Behavioral Fingerprinting"
- TGN paper: Rossi et al. "Temporal Graph Networks for Deep Learning"
- Datadog dataset: github.com/DataDog/malicious-software-packages-dataset
- Contact: [Your contact info]
