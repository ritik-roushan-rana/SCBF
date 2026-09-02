# Data Directory

This directory contains captured install-time event streams for training and validation.

## Structure

```
data/
├── clean/          # Legitimate package installations
└── malicious/      # Confirmed malicious packages
```

## Format

Each `.jsonl` file contains one event per line in JSON format:

```json
{"type": "exec", "pid": 1234, "ppid": 1233, "comm": "python3", "ts": 166627099800}
{"type": "open", "pid": 1234, "fname": "/tmp/site-packages/requests/__init__.py", "ts": 166657638891}
```

### Event Types

- **exec**: Process spawn (execve syscall)
- **open**: File access (openat syscall)
- **connect**: Network connection attempt (tcp_connect)

### Fields

- `type`: Event type
- `pid`: Process ID
- `ppid`: Parent process ID (exec only)
- `comm`: Command name (exec only)
- `fname`: File path (open only)
- `ts`: Nanosecond timestamp (monotonic)

## Collection

**Clean data**: Top PyPI packages
```bash
sudo python scripts/collect_clean_data.py
```

**Malicious data**: Datadog malicious package dataset
```bash
sudo python scripts/collect_malicious_data.py
```

## Current Dataset

- Clean packages: 60+ (requests, numpy, django, flask, etc.)
- Malicious samples: 99 (Datadog confirmed malicious)
- Average events per package: ~2000-4000

## Notes

- Event captures are deterministic per package/version
- Noise filtering applied (pip internals, __pycache__, etc.)
- Timestamps are kernel monotonic clock (nanoseconds)
