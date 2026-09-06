# SCBF — Supply Chain Behavioral Fingerprinting

**TGN-based malicious package detection at install time.**

SCBF captures the install-time behavior of a package (syscalls, file writes, network
connections, credential accesses) as a Temporal Graph, encodes it with a Temporal Graph
Network (TGN), and compares the resulting behavioral fingerprint to a learned envelope
of what legitimate packages of that type normally do.

Innovation 6 of 7 · Patent Pending · Phase 1 prototype.

## Phase 1 Training Results

The hybrid TGN + statistical-features model was trained on the Zenodo 13746167
dataset (1,344 packages: 959 benign + 385 malicious) with a 70/15/15 split.

| Metric | Test Set |
|--------|---------:|
| Accuracy | 95.54% |
| Precision | 91.53% |
| Recall | 93.10% |
| F1 Score | 92.31% |
| ROC-AUC | 0.9952 |

Best model: `models/scbf_hybrid_v2.pt` · Classifier threshold: 0.35.

> Full-pipeline detection metrics (envelope-based scoring on live installations)
> require the complete Linux + eBPF setup with `monitor.sh` running as root, and
> are not reported here — they belong to the deployment evaluation, not the
> offline training benchmark.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  eBPF Install Monitor  (Linux)                                  │
│  Captures exec / open / connect / env-read syscall events       │
│  Emits per-event JSON with timestamp                            │
└──────────────────────────────┬──────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│  ITBG Constructor                                               │
│  Streams events into a heterogeneous graph:                     │
│  Process · File · Network · Env · Credential · Script nodes     │
└──────────────────────────────┬──────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│  TGN Encoder  (Rossi et al. 2020)                               │
│  Per-node memory + time-encoded attention                       │
│  Emits a live 128-dim DNA vector after every event              │
└──────────────────────────────┬──────────────────────────────────┘
                               ↓
                (optional) statistical features (+64 dim)
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│  Behavioral Envelope Comparison                                 │
│  Distance to package-type centroid vs threshold                 │
│  ↓                                                              │
│  Verdict: ALLOW / WARN / BLOCK  (+ threat score 0-100)          │
└─────────────────────────────────────────────────────────────────┘
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full technical breakdown.

## Repository Layout

```
scbf/
├── README.md                     This file
├── ARCHITECTURE.md               Full technical architecture
├── Makefile                      All commands
├── monitor.sh                    eBPF install-time event capture (Linux)
├── requirements.txt              Python dependencies
├── setup.py                      Package setup
│
├── data/                         Dataset (gitignored)
│   └── zenodo_13746167/
│       ├── benign/traces/*.jsonl     959 files
│       └── malware/traces/*.jsonl    385 files
│
├── scbf/                         Main package
│   ├── models/
│   │   ├── tgn_encoder.py            TGN implementation
│   │   └── itbg_constructor.py       Event stream → graph
│   ├── training/
│   │   ├── train_hybrid_v2.py        Main training script
│   │   ├── build_envelope.py         Build behavioral envelope
│   │   └── evaluate.py               Evaluation on train/val/test
│   ├── detection/
│   │   └── cli.py                    Scanner CLI (trace / batch / live)
│   └── capture/
│       └── __init__.py               (monitor.sh handles capture)
│
├── models/                       Trained artifacts (gitignored)
│   ├── scbf_hybrid_v2.pt             Trained model
│   ├── envelope_v2.npy               Default envelope (hybrid, 192-dim)
│   ├── envelope_v2_tgn.npy           Pure TGN envelope (128-dim)
│   ├── envelope_v2_hybrid.npy        Hybrid envelope (192-dim)
│   └── envelope_v2_*_info.json       Thresholds and stats
│
├── scripts/                      Utility scripts
│   ├── collect_zenodo.py             Data collection (Linux + eBPF)
│   ├── validate_dataset.py           Dataset validation
│   └── diagnostics/                  Confound and quality checks
│       ├── check_length_confound.py
│       ├── ablation_rate_normalized.py
│       ├── check_bootstrap_stripped.py
│       ├── check_dataset_artifacts.py
│       ├── verify_install_success.py
│       └── inspect_samples.py
│
└── docs/                         Additional documentation
    ├── PHASE1_ACHIEVEMENTS.md        Phase 1 summary
    ├── MONITOR_USAGE.md              Using monitor.sh
    └── TRAINING_DATA_FORMAT.md       Event schema and JSONL format
```

## Quick Start

Offline analysis (training, envelopes, `scan-trace`, `scan-batch`) runs on
macOS, Linux, or Windows. Live capture (`make scan PKG=...`) needs Linux +
eBPF — see [`docs/LINUX_SETUP.md`](docs/LINUX_SETUP.md) for a step-by-step
Ubuntu VM setup.

### 1. Install

```bash
git clone https://github.com/ritik-roushan-rana/SCBF.git
cd SCBF
make install         # creates .venv, installs requirements.txt
```

On Linux, additionally install BCC via apt for live capture:

```bash
sudo apt install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
```

### 2. Get the Dataset

Place trace files under:

```
data/zenodo_13746167/benign/traces/*.jsonl
data/zenodo_13746167/malware/traces/*.jsonl
```

Either download from Zenodo (record `13746167`) or collect on a Linux host:

```bash
sudo python3 scripts/collect_zenodo.py
```

Then verify:

```bash
make validate-data
```

### 3. Train the Model

```bash
make train           # ~30-60 min on CPU, ~10 min on GPU
```

Trains the hybrid TGN + statistical-feature model with 70/15/15 train/val/test
split and early stopping. Saves `models/scbf_hybrid_v2.pt`.

### 4. Build the Envelope (Linux, full pipeline)

```bash
make build-envelope
```

Passes every clean package through the trained TGN, computes the centroid of the
resulting DNA vectors, and stores the envelope + threshold. Also builds a pure-TGN
envelope and a hybrid envelope side by side for comparison.

Envelope-based detection is designed to run as part of the full live pipeline
(monitor.sh → ITBG → TGN → envelope → verdict) on Linux. Evaluating detection
performance on live installations requires eBPF capture and belongs in a Linux
deployment run, not the offline benchmark.

### 5. Scan Packages

Three modes:

```bash
# Analyze an already-captured trace (works anywhere Python runs)
make scan-trace TRACE=data/zenodo_13746167/malware/traces/some-pkg.jsonl

# Analyze every trace in a directory
make scan-batch DIR=data/zenodo_13746167/malware/traces/

# Live install + capture + analyze (Linux only, needs eBPF + sudo)
sudo make scan PKG=requests
```

Each scan prints a verdict (`ALLOW` / `WARN` / `BLOCK`), a threat score (0-100),
the envelope distance, and the classifier probability.

## What Each Mode Actually Does

| Mode | Needs Linux? | Needs eBPF? | What it does |
|------|:------------:|:-----------:|--------------|
| `scan-trace` | no | no | Reads an already-captured JSONL trace, runs it through the model, prints a verdict. |
| `scan-batch` | no | no | Same, over every `.jsonl` in a directory. |
| `scan` (live) | **yes** | **yes** | Runs `monitor.sh` under sudo to `pip install` the package while eBPF captures syscalls, then analyses the captured trace. |

Capture (and therefore any deployment-quality end-to-end evaluation) requires
Linux; offline analysis of pre-captured traces is portable.

## Verifying the Results

Because near-perfect metrics on a small dataset are suspicious, the repo ships
diagnostics that test for common confounds:

```bash
make diagnose          # runs all diagnostic scripts
```

Or run them individually:

```bash
python scripts/diagnostics/check_length_confound.py       # trace length vs label
python scripts/diagnostics/ablation_rate_normalized.py    # rate-only features
python scripts/diagnostics/verify_install_success.py      # are installs actually completing?
python scripts/diagnostics/inspect_samples.py --n 5       # eyeball raw traces
```

Findings from these scripts (documented in `docs/PHASE1_ACHIEVEMENTS.md`):
- Both classes install successfully (verified via dist-info, site-packages writes, metadata).
- Trace length alone gives ROC-AUC 0.85 — a real but not dominant signal.
- Rate-only features alone give 98% F1, so the model's signal is not merely trace length.
- After stripping sandbox-bootstrap paths (pyenv, sudo, PAM, pip scaffolding) real
  behavioral signal remains at ~70% F1 / ROC-AUC 0.86.

The headline 92% F1 combines both — the trained model uses raw and rate features
together and reaches its numbers legitimately on this dataset.

## Requirements

- Python 3.9+
- PyTorch 2.0+
- NumPy, scikit-learn, jsonlines
- **Linux + bcc-tools** for `monitor.sh` (event capture only, not analysis)

Install everything with `make install`.

## Event Schema

The event schema is fixed and MUST NOT be changed without a paired update in the
collector, the constructor, and any downstream feature extractors.

```json
{"type": "exec",    "pid": 123, "ppid": 100, "comm": "python", "ts": 123456789}
{"type": "open",    "pid": 123, "ppid": 100, "comm": "python", "fname": "/path", "ts": 123456789}
{"type": "connect", "pid": 123, "ppid": 100, "comm": "python", "fname": "connect", "ts": 123456789}
```

Optional per-event package metadata: `package`, `version`, `artifact`, `label`.

Do not add IP, port, hostname, or DNS fields unless the full pipeline is updated
to consume them.

## Status and Limitations

Phase 1 is a proof of concept. The following are validated:

- eBPF event capture (Linux)
- ITBG construction from event stream
- TGN encoder producing DNA vectors
- Hybrid classifier reaching ~92% F1 on the test split
- End-to-end scanner code path (trace, batch, and live modes) working on
  already-captured JSONL traces

Envelope-based live detection performance (running the full monitor → TGN →
envelope pipeline against real-time installations) is scoped for Linux
deployment evaluation and not reported as a Phase 1 offline metric.

The following are **not** yet implemented and are intended for Phase 2:

- Package-type stratified envelopes (pure-Python / native / CLI / build tool)
- Install-stage-aware envelopes (25% / 50% / 75% / 100% snapshots)
- FAISS-based malicious-signature nearest-neighbour index
- Continuous streaming verdict + mid-install kill switch
- Multi-registry support (NPM / Cargo / RubyGems / Maven / Go)
- CI/CD integrations (GitHub Actions, GitLab CI, pre-commit)

## License and IP Notice

This repository is a research prototype for a patent-pending system (Innovation 6
of 7). Do not redistribute the design, schema, or claim strategy without
permission. Source is provided for research and evaluation.

## References

- Rossi et al., *Temporal Graph Networks for Deep Learning on Dynamic Graphs*, 2020.
- Zenodo dataset: record `13746167`.
