# Rich telemetry for the NPM detector

The RQ1 NPM traces carry only `{type, pid, ppid, comm, fname, ts}`. With those
fields a malicious package that compiles a native module looks identical to a
benign one that does the same, which caps the install-time detector at ~90% F1
(see `models/npm_evaluation_results*.json`). `scbf/training/npm_rich_features.py`
adds 87 features that use three extra signals. All of them are zero when the
field is missing, so old traces keep working.

## Fields the collector must add

| event type | field      | value                                             |
|------------|------------|---------------------------------------------------|
| exec       | `argv`     | list of strings (or `cmdline`: one string)        |
| connect    | `daddr`    | destination IP as string (`""` for unix sockets)  |
| connect    | `dport`    | destination port (int)                            |
| connect    | `family`   | `"inet"`, `"inet6"` or `"unix"`                   |
| any        | `phase`    | `"install"` or `"require"`                        |

### Capture-side changes to `monitor.sh`

1. **argv** – in `sys_enter_execve`, after reading `args->filename`, walk
   `args->argv[i]` for `i < 16` with `bpf_probe_read_user(&ptr, ...)` +
   `bpf_probe_read_user_str(buf, 128, ptr)` and ship them in a second perf
   event (or a fixed `char argv[16][128]` block). Join in userspace into
   `event["argv"]`.
2. **connect destination** – in `sys_enter_connect`, read
   `struct sockaddr sa` from `args->uservaddr`; if `sa.sa_family == AF_INET`
   read `sockaddr_in` (`sin_addr.s_addr`, `ntohs(sin_port)`), if `AF_INET6`
   read `sockaddr_in6`, else mark `"unix"`. Emit `daddr`, `dport`, `family`.
3. **require phase** – after `npm install <pkg>` finishes, run
   `node -e "require('<pkg>')"` under the same tracer and tag every event
   emitted after that point with `"phase": "require"` (everything before is
   `"install"`).

## Training with the rich features

```bash
python -m scbf.training.find_inert_npm                 # optional: list install-inert malware
python -m scbf.training.train_npm_hybrid --rich --exclude-inert
python -m scbf.training.evaluate_npm models/scbf_npm_hybrid_v1.pt
```

`--rich` switches the stat encoder to 386 inputs (299 base + 87 rich) and uses
a separate preprocessing cache (`npm_preprocessed_cache_rich.pt`). The
checkpoint records the feature set, and inference (`NPMHybridClassifier.forward`)
selects base vs. rich features from the checkpoint automatically, so
`evaluate_npm.py` and the CLI need no flags.
