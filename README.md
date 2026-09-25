# SCBF v2 — Supply Chain Behavioral Fingerprinting

Detects malicious PyPI packages from their **install-time behavior**, captured
with eBPF and modeled as a temporal graph.

```
eBPF Install Monitor (Linux)
  exec / open+write / connect / credential-read events, JSON per event
        |
ITBG Constructor
  heterogeneous temporal graph:
  Process · File · Network · Env · Credential · Script
        |
TGN Encoder (Rossi et al. 2020)
  per-node memory + time-encoded attention -> 128-dim DNA vector per event
        |
  + 51 statistical features
        |
Hybrid Classifier / Behavioral Envelope
  verdict: ALLOW / WARN / BLOCK  + threat score
```

## Results

Held-out test split (210 traces, 59 malicious), hybrid TGN, threshold tuned on
validation only, test scored exactly once:

| Split | n | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|---|
| Train | 974 | 96.00% | 97.17% | 88.24% | 92.49% | 0.9866 |
| Val | 209 | 97.13% | 100.00% | 89.66% | 94.55% | 0.9502 |
| **Test** | **210** | **95.71%** | **96.30%** | **88.14%** | **92.04%** | **0.9762** |

Train-test F1 gap +0.45%. An independently trained variant (different class
weighting) reached test F1 91.89% / AUC 0.9793 on the same split.

Against published baselines on the same PyPI benchmark:

| Tool | Precision | Recall | F1 |
|---|---|---|---|
| **SCBF** | 0.9630 | **0.8814** | **0.9204** |
| OSCAR (ASE '24) | 0.99 | 0.85 | 0.91 |
| Guarddog | 0.89 | 0.94 | 0.91 |

Not like-for-like: OSCAR is zero-shot over all 500 malicious packages; SCBF is
supervised and scored on 59 held-out malicious samples. Bootstrap CI on F1 is
about +/-4%. The defensible claim is parity-or-better at a different operating
point, with ~30x lower latency.

Ablation: graph only, no statistical fusion -> val F1 86.79% (vs 94.55%).

## Pipeline

```bash
make install
sudo make capture BENIGN=data/raw/benign MALWARE=data/raw/malware
make audit          # <- before trusting any metric
make train
make evaluate
```

## Why v2 exists

v1 reported 92.31% test F1. That number was not real.

The benchmark traces had a **collection artifact**: 97.2% of benign traces
contained `/dev/pts` (a TTY was attached during capture) and 0% of malicious
ones did. Consequences measured directly:

| | F1 |
|---|---|
| one-line rule, "malicious if <5 `/dev` accesses" | 96.48% |
| trained hybrid TGN | 92.31% |
| same model, artifact removed | 52.53% |

The model was detecting the capture environment, not malicious behavior.

The capture was also **blind to the behaviors that define malware**:

| Signal | v1 | v2 |
|---|---|---|
| `execve` | captured in 1 of 1344 traces | tracked in-kernel at fork |
| `connect` destination | literal string `"connect"` | real IP + port |
| read vs write | indistinguishable | `openat` flags recorded |

So v1 was asked to detect malware from "which paths did `python` open" — and
when that wasn't enough, it took the artifact instead.

## What v2 changes

1. **Capture records behavior.** A `sched_process_fork` tracepoint inherits
   the tracked flag in-kernel, closing the race that dropped every
   short-lived `curl`/`sh`. Connect reads the sockaddr. `openat` keeps flags.
2. **Collection cannot separate the classes.** `capture/collect_dataset.py`
   runs both classes through one interleaved queue, one harness, never a TTY,
   and records an environment fingerprint.
3. **The audit is a gate, not a suggestion.** `make train` refuses to run on a
   dataset that fails `scbf.audit.leakage` unless you pass `FORCE=1`.
4. **Features describe behavior**, not sandbox strings — spawned binaries,
   external destinations, non-standard ports, writes outside site-packages,
   persistence writes, credential reads.
5. **Graph nodes are role-bucketed**, so literal sandbox paths never become
   node identities.

## Reporting rule

Report metrics only from a dataset where `make audit` passes, and state the
audit result alongside them. A number from an un-audited dataset is a
statement about your sandbox.

## Layout

```
capture/     monitor.sh (eBPF), collect_dataset.py (interleaved collection)
scbf/graph/  ITBG constructor
scbf/models/ TGN encoder
scbf/features/ statistical features
scbf/audit/  leakage audit
scbf/training/ train, evaluate
scbf/detection/ scanning CLI
```
