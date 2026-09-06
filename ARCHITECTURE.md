# SCBF Architecture

Detailed technical breakdown of the Supply Chain Behavioral Fingerprinting system.

## System Overview

SCBF is a five-stage pipeline that converts install-time syscall events into a
verdict on whether a package is malicious. Each stage can be tested and replaced
independently.

```
   Install command                Event capture              Behavioral graph
  (pip / npm / cargo)  ──────►    eBPF monitor    ──────►    ITBG constructor
                                                                    │
                                                                    ▼
    Verdict + report            Envelope + signatures         TGN encoder
   ALLOW / WARN / BLOCK ◄──────    (per package type)  ◄──── (DNA vector)
```

## Stage 1 — eBPF Event Capture

**File:** `monitor.sh` (root)  
**Runs on:** Linux only (requires `bcc-tools` + root).

Attaches to kernel tracepoints for a small set of syscalls and writes one JSON
event per line to stdout / a file. The set is intentionally narrow — only the
events that carry supply-chain-relevant signal are captured:

| Syscall class | Rationale |
|---------------|-----------|
| `execve` | Every subprocess the installer spawns. |
| `openat` | File reads and writes (site-packages, /tmp, credential files). |
| `connect` | Any outbound socket the installer opens. |
| `execveat` | Script execution (bash / sh / python via exec). |

Each captured event carries `pid`, `ppid`, `comm`, `type`, `fname`, `ts` (ns).
The schema is fixed — see `README.md` § Event Schema.

The monitor buffers events in a perf ring and streams them to disk without
blocking the installer, so the observed timing reflects real install behavior
rather than measurement lag.

## Stage 2 — ITBG Constructor

**File:** `scbf/models/itbg_constructor.py`  
**Runs on:** any platform.

Consumes the event stream in arrival order and materialises the Install-Time
Behavioral Graph:

**Node types**

| Type | Represents |
|------|-----------|
| `process` | A running process; keyed by PID within the session. |
| `file` | A file path touched by any process. |
| `network` | A destination (currently just "connect" — no IP/port). |
| `env` | An environment variable read event. |
| `credential` | A read of a credential-shaped file (`~/.aws`, `~/.ssh`, `.env`). |
| `script` | A script execution (shell / interpreter). |

**Edge types**

| Edge | Direction | Meaning |
|------|-----------|---------|
| `spawns` | process → process | ppid → pid via execve. |
| `writes_file` | process → file | open with write intent. |
| `connects_to` | process → network | Outbound socket. |
| `reads_env` | process → env | Environment variable read. |
| `reads_credential` | process → credential | Credential-file open. |
| `executes_script` | process → script | Shell/interpreter invocation. |

Each edge is timestamped and pushed to the TGN encoder as soon as it is
constructed — there is no batch step where the whole graph exists in isolation.

## Stage 3 — TGN Encoder

**File:** `scbf/models/tgn_encoder.py`  
**Reference:** Rossi et al., *Temporal Graph Networks for Deep Learning on
Dynamic Graphs*, 2020.

Three sub-modules, all standard TGN:

### 3.1 `TimeEncode`
Functional (Time2Vec-style) encoding of inter-event Δt.
`cos(W · Δt)` where `W ∈ ℝ^{d×1}` is learnable.
Distinguishes near-instantaneous events (credential-read-then-connect) from
temporally separated ones (setup, wait, act).

### 3.2 `TGNMemory`
A per-node memory bank `M ∈ ℝ^{N × d_mem}` plus a `last_update ∈ ℝ^N` vector.
Updated with a GRU cell:

```
msg = cat(M[src], M[dst], edge_feat, time_encode(t - last_update[src]))
M[dst] ← GRUCell(msg, M[dst])
last_update[dst] ← t
```

Memory persists across the whole install session and is reset per package.

### 3.3 `TemporalAttentionEmbedding`
Multi-head attention over the target node's recent temporal neighbourhood,
weighted by learned time encoding, followed by a `LayerNorm` projection.

Output: **128-dim Install-Time Behavioral DNA vector**, L2-normalised.

The DNA vector is emitted after every event, not just at end-of-install. This is
what enables mid-install verdicts.

**Note:** L2 normalisation puts DNA vectors on the unit sphere, so pairwise
distances are bounded in [0, 2]. This is why the pure-TGN envelope alone gives
weak class separation on the current dataset (see § Stage 5).

## Stage 4 — Hybrid Feature Fusion

**File:** `scbf/training/train_hybrid_v2.py` (`HybridClassifierV2`)

The DNA vector by itself does not carry enough separation, on this dataset, to
reach the reported classifier F1. `HybridClassifierV2` augments it with 45
hand-crafted statistical features computed from the same event stream:

- Event-type ratios (exec / open / connect proportion of total).
- Path-category proportions (`/tmp`, `/.ssh`, `/root`, `/usr`, `site-packages`, ...).
- Suspicious command proportions (curl/wget, nc, base64, chmod, ssh/scp).
- Time-based features (avg/max/min inter-event gap, log(events/sec)).
- Path-shape features (max depth, average length, distinct parent directories).
- Text pattern flags (base64-looking segments, http:// in paths).

The 45 features are encoded through a small MLP (`45 → 64`) and concatenated
with the 128-dim TGN DNA to form a **192-dim combined vector**. This combined
vector feeds a residual classifier head (`192 → 128 → 128 → 64 → 1`) with
LayerNorm + GELU + Dropout.

**Two ways to use the model at inference:**

| Mode | Vector | Purpose |
|------|--------|---------|
| Pure TGN | 128-dim DNA only | Matches patent spec § 5.3 verbatim. |
| Hybrid | 192-dim (DNA + stats) | Wider inter-class distance under the L2 metric. |

Both are supported in `build_envelope.py` — set `BUILD_BOTH = True` (default).

## Stage 5 — Verdict Engine

**File:** `scbf/detection/cli.py`

At inference time, the trained model is used to extract a DNA vector (pure-TGN
or hybrid) for the target trace. Detection is then a distance comparison:

```
distance = ‖dna − envelope_centroid‖₂

if distance ≥ threshold           → BLOCK   (envelope_v2_info.json.threshold)
elif distance ≥ mean + 1.5·std    → WARN
else                              → ALLOW
```

The threshold is derived per patent spec § 8.3 (mean + 2.5·std of clean-distance
distribution) during envelope construction. A threat score in [0, 100] is
computed for reporting: 0 = at centroid, 75 = at threshold, 100 = well beyond.

The classifier's sigmoid output is also included in reports as an independent
second opinion.

### Live vs Offline

- **Offline (`scan-trace` / `scan-batch`):** reads existing JSONL, computes
  DNA, distance, verdict. Works anywhere Python runs.
- **Live (`scan`):** runs `monitor.sh` under sudo to `pip install` the target
  package in a sandbox, waits for capture to finish, then feeds the resulting
  trace into the same offline pipeline. Linux only.

## Training

**File:** `scbf/training/train_hybrid_v2.py`

- **Split:** 70/15/15 train/val/test, stratified by label, fixed seed.
- **Loss:** Focal BCE with `pos_weight` = (n_clean / n_mal) ≈ 2.49.
- **Optimiser:** AdamW, lr 3e-4, weight decay 1e-4.
- **Schedule:** Cosine annealing with warm restarts (`T_0=10, T_mult=2`).
- **Regularisation:** LayerNorm everywhere, dropout 0.2 / 0.3 / 0.4, gradient
  clipping at norm 1.0.
- **Early stopping:** patience 8 epochs on validation F1.
- **Threshold selection:** grid search on validation set after training;
  optimal 0.35 for the current dataset.

Full training run: ~30-60 min on Mac CPU, ~10 min on a T4 GPU.

**Evaluation** — `scbf/training/evaluate.py` (run via `make evaluate`) reloads
the trained model + `split_info.json` and re-scores all three splits
(train / val / test) with the tuned threshold. Output is both a printed report
and `models/evaluation_results.json`. This is the same code path used for the
metrics table in `README.md` / `docs/PHASE1_ACHIEVEMENTS.md`.

## Envelope Construction

**File:** `scbf/training/build_envelope.py`

Per patent spec § 8.3:

1. Run every clean package's event stream through the trained model.
2. Collect the DNA vectors (either pure-TGN or hybrid).
3. Compute centroid = mean over clean DNA vectors.
4. Compute per-sample distance to centroid; store mean and std.
5. Threshold = mean + 2.5 · std.

Both envelopes are saved:

```
models/envelope_v2_tgn.npy        # 128-dim, matches spec verbatim
models/envelope_v2_hybrid.npy     # 192-dim, wider inter-class distance
models/envelope_v2.npy            # alias → hybrid (default)
```

## Diagnostics and Confound Testing

**Directory:** `scripts/diagnostics/`

Because a 92% F1 result on a small dataset should not be trusted at face value,
the repo ships four diagnostic scripts that stress-test the result:

| Script | What it tests |
|--------|---------------|
| `check_length_confound.py` | Is the signal just "malicious traces are shorter"? |
| `ablation_rate_normalized.py` | Do rate features work independently of length? |
| `check_dataset_artifacts.py` | Are the classes captured with different tooling? |
| `check_bootstrap_stripped.py` | Do results survive removing pyenv / sudo / PAM / pip scaffolding paths? |
| `verify_install_success.py` | Do malicious installs actually complete (dist-info, metadata, site-packages)? |
| `inspect_samples.py` | Manual side-by-side of raw traces for eyeballing. |

Findings from these on the Zenodo dataset are summarised in
`docs/PHASE1_ACHIEVEMENTS.md`.

## Model Files

After a full training + envelope run, the `models/` directory contains:

```
scbf_hybrid_v2.pt              trained hybrid model (state dict)
envelope_v2.npy                default envelope (hybrid, 192-dim)
envelope_v2_hybrid.npy         explicit hybrid envelope
envelope_v2_hybrid_info.json   threshold + statistics
envelope_v2_tgn.npy            pure-TGN envelope (128-dim, matches spec § 5.3)
envelope_v2_tgn_info.json      threshold + statistics
envelope_v2_*_covariance.npy   full covariance matrices (optional, for Mahalanobis)
```

None of these are committed to git; they are gitignored and rebuilt from
`make train && make build-envelope`.

## What Is Not in Phase 1

Explicit non-goals for this phase, and their patent-spec references:

- **Package-type stratification** (spec § 3, § 8.3). A single envelope is
  used across all Python packages regardless of whether they are libraries,
  CLI tools, or native extensions.
- **Install-stage envelopes** (spec § 8.3). The envelope is computed from
  end-of-install DNA vectors only, not at 25% / 50% / 75% snapshots.
- **FAISS malicious-signature index** (spec § 5.4). There is no known-malicious
  nearest-neighbour lookup; only distance-to-clean-envelope is used.
- **Streaming verdict / mid-install kill-switch** (spec § 4.6, claim 6). The
  scanner is offline: it reads a completed trace, not a live stream.
- **Multi-registry support** (spec § 2). PyPI only.
- **CI/CD integration** (spec § 6). No GitHub Actions / GitLab CI hooks yet.

All of these are Phase 2.
