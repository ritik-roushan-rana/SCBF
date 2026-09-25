"""
Statistical features over an install trace.

These are built around the signals the FIXED monitor records. The previous
generation of this code declared features like `curl_wget`, `nc_ncat`,
`shell` and `n_exec` over traces where execve was captured in 1 of 1344
cases -- those features were structurally zero, and the model fell back on
a collection artifact instead. Every feature here is checked by
`scbf.audit.leakage` before training.

Three signal groups the old capture could not see at all:

  exec    - what the package SPAWNS (shells, curl, wget, base64, chmod).
            This is the single strongest malware indicator at install time.
  connect - WHERE it connects (destination IP and port), so C2 contact is
            distinguishable from pip talking to PyPI.
  write   - whether a file was OPENED FOR WRITING, so "wrote to
            ~/.ssh/authorized_keys" is distinguishable from reading a file.

Rate features are included alongside counts deliberately: raw counts track
trace length, which is a property of package size rather than intent.
"""

from collections import Counter

import numpy as np

# Binaries whose appearance during a package install is meaningful.
SUSPICIOUS_BINS = {
    "curl", "wget", "nc", "ncat", "netcat", "base64", "chmod", "chown",
    "sh", "bash", "zsh", "dash", "ksh", "openssl", "gpg", "tar", "unzip",
    "systemctl", "crontab", "at", "ssh", "scp", "nohup", "setsid",
}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
NET_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "dig", "nslookup", "ssh", "scp"}

# Paths that matter if a package reads them.
CREDENTIAL_HINTS = (
    "/.ssh/", "/.aws/", "/.config/gcloud", "/.docker/config", "/.netrc",
    "/.git-credentials", "/.npmrc", "/.pypirc", "/etc/shadow",
    "/.mozilla/", "/.config/google-chrome", "/Login Data", "/.kube/config",
)
# Paths that matter if a package WRITES them.
PERSISTENCE_HINTS = (
    "/.bashrc", "/.bash_profile", "/.zshrc", "/.profile", "/etc/cron",
    "/.ssh/authorized_keys", "/etc/systemd", "/.config/autostart",
    "/etc/rc.local", "/.local/bin/",
)

STANDARD_PORTS = {80, 443}

FEATURE_NAMES = [
    # volume / shape
    "n_events", "n_open", "n_connect", "n_exec",
    "r_open", "r_connect", "r_exec",
    "u_pids", "u_comms", "u_files", "r_u_files",
    # exec behavior  (invisible to the old capture)
    "n_susp_exec", "r_susp_exec", "n_shell_exec", "n_nettool_exec",
    "u_exec_bins", "max_proc_depth", "n_exec_outside_py",
    # network behavior (destination was invisible to the old capture)
    "u_dest_ips", "n_ext_connect", "r_ext_connect", "u_dest_ports",
    "n_nonstd_port", "r_nonstd_port", "has_ext_connect",
    # write behavior  (read/write was invisible to the old capture)
    "n_writes", "r_writes", "n_write_outside_sp", "r_write_outside_sp",
    "n_write_home", "n_write_hidden", "n_persistence_write",
    # credential access
    "n_cred_read", "r_cred_read", "has_cred_read", "n_ssh_access",
    # filesystem shape
    "n_tmp", "r_tmp", "n_home", "r_home", "n_hidden", "r_hidden",
    "n_system", "n_proc_fs", "n_site_packages", "r_site_packages",
    # temporal
    "duration_s", "events_per_s", "t_first_connect_frac", "t_first_exec_frac",
    "burstiness",
]


def _safe_div(a, b):
    return a / b if b else 0.0


def extract_features(events) -> np.ndarray:
    """Return the feature vector for one trace. Never raises on odd input."""
    n = len(events)
    if n == 0:
        return np.zeros(len(FEATURE_NAMES), dtype=np.float32)

    f = []
    types = Counter(e.get("type", "") for e in events)
    n_open = types.get("open", 0)
    n_conn = types.get("connect", 0)
    n_exec = types.get("exec", 0)

    pids = set(e.get("pid", 0) for e in events)
    comms = set(e.get("comm", "") for e in events)
    paths = [e.get("fname", "") for e in events if e.get("fname")]
    files = set(p for p in paths if p.startswith("/"))

    f += [n, n_open, n_conn, n_exec,
          _safe_div(n_open, n), _safe_div(n_conn, n), _safe_div(n_exec, n),
          len(pids), len(comms), len(files), _safe_div(len(files), max(1, len(paths)))]

    # ---- exec behavior -----------------------------------------------
    exec_events = [e for e in events if e.get("type") == "exec"]
    exec_bins = []
    for e in exec_events:
        target = e.get("fname", "") or e.get("comm", "")
        exec_bins.append(target.rsplit("/", 1)[-1])
    susp = [b for b in exec_bins if b in SUSPICIOUS_BINS]
    shells = [b for b in exec_bins if b in SHELLS]
    nets = [b for b in exec_bins if b in NET_TOOLS]
    non_py = [b for b in exec_bins if not b.startswith("python") and b not in ("pip", "sudo")]

    # Process nesting depth via pid/ppid chains.
    parent = {}
    for e in events:
        p, pp = e.get("pid"), e.get("ppid")
        if p is not None and pp is not None and p != pp:
            parent.setdefault(p, pp)
    depth = 0
    for p in list(parent)[:2000]:
        d, cur, seen = 0, p, set()
        while cur in parent and cur not in seen and d < 64:
            seen.add(cur)
            cur = parent[cur]
            d += 1
        depth = max(depth, d)

    f += [len(susp), _safe_div(len(susp), max(1, len(exec_bins))), len(shells),
          len(nets), len(set(exec_bins)), depth, len(non_py)]

    # ---- network behavior --------------------------------------------
    conn = [e for e in events if e.get("type") == "connect"]
    dests = set()
    ports = set()
    ext = 0
    nonstd = 0
    for e in conn:
        d = e.get("daddr")
        p = e.get("dport")
        if d:
            dests.add(d)
            # Anything off-loopback/private is an external contact.
            if not (d.startswith("127.") or d.startswith("10.")
                    or d.startswith("192.168.") or d == "0.0.0.0"):
                ext += 1
        if p:
            ports.add(p)
            if p not in STANDARD_PORTS:
                nonstd += 1

    f += [len(dests), ext, _safe_div(ext, max(1, len(conn))), len(ports),
          nonstd, _safe_div(nonstd, max(1, len(conn))), float(ext > 0)]

    # ---- write behavior ----------------------------------------------
    writes = [e for e in events if e.get("write")]
    wpaths = [e.get("fname", "") for e in writes]
    w_outside = [p for p in wpaths if "site-packages" not in p and p.startswith("/")]
    w_home = [p for p in wpaths if "/home/" in p or p.startswith("/root/")]
    w_hidden = [p for p in wpaths if "/." in p]
    w_persist = [p for p in wpaths if any(h in p for h in PERSISTENCE_HINTS)]

    f += [len(writes), _safe_div(len(writes), n), len(w_outside),
          _safe_div(len(w_outside), max(1, len(writes))), len(w_home),
          len(w_hidden), len(w_persist)]

    # ---- credential access --------------------------------------------
    creds = [p for p in paths if any(h in p for h in CREDENTIAL_HINTS)]
    ssh = [p for p in paths if "/.ssh" in p]
    f += [len(creds), _safe_div(len(creds), n), float(len(creds) > 0), len(ssh)]

    # ---- filesystem shape ---------------------------------------------
    tmp = [p for p in paths if p.startswith("/tmp") or p.startswith("/var/tmp")]
    home = [p for p in paths if "/home/" in p or p.startswith("/root/")]
    hidden = [p for p in paths if "/." in p]
    system = [p for p in paths if p.startswith("/usr/") or p.startswith("/etc/")]
    procfs = [p for p in paths if p.startswith("/proc/")]
    sp = [p for p in paths if "site-packages" in p]
    np_ = max(1, len(paths))
    f += [len(tmp), _safe_div(len(tmp), np_), len(home), _safe_div(len(home), np_),
          len(hidden), _safe_div(len(hidden), np_), len(system), len(procfs),
          len(sp), _safe_div(len(sp), np_)]

    # ---- temporal ------------------------------------------------------
    ts = [e.get("ts", 0) for e in events if e.get("ts")]
    if len(ts) > 1:
        t0, t1 = min(ts), max(ts)
        dur = (t1 - t0) / 1e9  # ns -> s
        eps = _safe_div(n, dur) if dur > 0 else 0.0
        first_conn = next((e.get("ts", t0) for e in events if e.get("type") == "connect"), None)
        first_exec = next((e.get("ts", t0) for e in events if e.get("type") == "exec"), None)
        span = max(1, t1 - t0)
        fc = (first_conn - t0) / span if first_conn else -1.0
        fe = (first_exec - t0) / span if first_exec else -1.0
        gaps = np.diff(np.array(sorted(ts), dtype=np.float64))
        burst = float(np.std(gaps) / (np.mean(gaps) + 1e-9)) if len(gaps) else 0.0
    else:
        dur = eps = burst = 0.0
        fc = fe = -1.0
    f += [dur, eps, fc, fe, burst]

    arr = np.array(f, dtype=np.float32)
    if arr.shape[0] != len(FEATURE_NAMES):
        raise RuntimeError(f"expected {len(FEATURE_NAMES)} features, built {arr.shape[0]}")
    return np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)


STAT_DIM = len(FEATURE_NAMES)
