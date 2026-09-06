"""
Event capture layer.

The active capture path is the top-level `monitor.sh` bash script, which uses
eBPF (bpftrace / bcc) on Linux to stream install-time syscall events as JSON
lines. There is no Python capture module in Phase 1 — the analysis pipeline
consumes the JSONL trace written by `monitor.sh`.

See:
- monitor.sh (repo root)
- docs/MONITOR_USAGE.md
"""

__all__ = []
