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

import os

import numpy as np

# Binaries whose appearance during a package install is meaningful.
SUSPICIOUS_BINS = {
    "curl", "wget", "nc", "ncat", "netcat", "base64", "chmod", "chown",
    "sh", "bash", "zsh", "dash", "ksh", "openssl", "gpg", "tar", "unzip",
    "systemctl", "crontab", "at", "ssh", "scp", "nohup", "setsid",
}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}

# The package manager's OWN machinery. Anything else executing during an
# install is a package doing something, which is what we want to measure.
# This has to be ecosystem-specific: npm and node are npm's interpreter the
# way python and pip are pip's, so scoring them as "foreign binaries" made
# n_exec_outside_py fire on every npm trace of either class and contribute
# nothing but noise.
INSTALLER_BINS = {
    "pypi": ("python", "pip", "sudo"),
    "npm": ("node", "npm", "npx", "sudo"),
}


def _ecosystem():
    return os.environ.get("SCBF_ECOSYSTEM", "pypi")


def _is_installer_bin(b, eco):
    if eco == "npm":
        return b in INSTALLER_BINS["npm"] or b.startswith("node")
    return b.startswith("python") or b in ("pip", "sudo")
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
    _eco = _ecosystem()
    non_py = [b for b in exec_bins if not _is_installer_bin(b, _eco)]

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
    # Only the PACKAGE's credential access counts. sudo's PAM helper
    # (unix_chkpwd) reads /etc/shadow during privilege drop, which is
    # infrastructure, not behaviour -- and whether it fires depends on sudo's
    # timestamp cache, so it varies between captures of the SAME package.
    # Measured: rdquests-2.28.1 scored 0.96 in a capture where unix_chkpwd ran
    # and 0.005 in one where it did not. Counting it made the model partly
    # learn sudo's behaviour instead of the package's.
    BOOTSTRAP_CRED = ("/etc/shadow", "/etc/passwd", "/etc/group", "/etc/gshadow")
    BOOTSTRAP_COMM = {"sudo", "unix_chkpwd", "su", "pam_unix"}
    pkg_events = [e for e in events
                  if (e.get("comm") or "").rsplit("/", 1)[-1] not in BOOTSTRAP_COMM]
    pkg_paths = [e.get("fname", "") for e in pkg_events if e.get("fname")]
    creds = [p for p in pkg_paths
             if any(h in p for h in CREDENTIAL_HINTS)
             and not p.startswith(BOOTSTRAP_CRED)]
    ssh = [p for p in pkg_paths if "/.ssh" in p]
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

    if _eco == "npm":
        f += _npm_ancestry_features(events, parent)

    arr = np.array(f, dtype=np.float32)
    expected = len(FEATURE_NAMES_NPM) if _eco == "npm" else len(FEATURE_NAMES)
    if arr.shape[0] != expected:
        raise RuntimeError(f"expected {expected} features, built {arr.shape[0]}")
    return np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)


def _npm_ancestry_features(events, parent):
    """Who spawned what: the part of npm's attack signature the shared
    features cannot see.

    A preinstall payload is `npm -> sh -c "curl ..."`. Counting shells and
    curl invocations alone cannot separate that from npm's own tooling
    invoking a shell, because both produce the same binary names. What
    distinguishes them is ancestry, so these features ask whether a foreign
    binary ran as a DESCENDANT of the installer, and how deep.
    """
    comm_of = {}
    for e in events:
        pid = e.get("pid")
        if pid is not None and pid not in comm_of:
            comm_of[pid] = (e.get("comm") or "")

    def installer(pid):
        c = comm_of.get(pid, "")
        return c.startswith("node") or c.startswith("npm") or c in ("npx", "sudo")

    n_under = n_foreign_under = 0
    has_shell = has_net = 0.0
    depth_first = frac_first = 0.0
    foreign_bins = set()
    max_chain = 0
    total = max(1, len(events))

    for i, e in enumerate(events):
        if e.get("type") != "exec":
            continue
        pid, ppid = e.get("pid"), e.get("ppid")
        binname = (e.get("fname") or e.get("comm") or "").rsplit("/", 1)[-1]
        if ppid is not None and installer(ppid):
            n_under += 1
            if not _is_installer_bin(binname, "npm"):
                n_foreign_under += 1
        if _is_installer_bin(binname, "npm"):
            continue
        foreign_bins.add(binname)
        if binname in SHELLS:
            has_shell = 1.0
        if binname in NET_TOOLS:
            has_net = 1.0
        # depth of this pid in the process tree
        d, cur, seen = 0, pid, set()
        while cur in parent and cur not in seen and d < 64:
            seen.add(cur)
            cur = parent[cur]
            d += 1
        max_chain = max(max_chain, d)
        if depth_first == 0.0 and frac_first == 0.0:
            depth_first = float(d)
            frac_first = i / total

    n_node = n_node_sh = 0
    for e in events:
        if e.get("type") != "exec" or (e.get("comm") or "") != "node":
            continue
        n_node += 1
        if comm_of.get(e.get("ppid"), "") in SHELLS:
            n_node_sh += 1

    return [float(n_under), float(n_foreign_under), has_shell, has_net,
            depth_first, frac_first, float(len(foreign_bins)), float(max_chain),
            float(n_node), float(n_node_sh)]


# npm-only features. npm's attack signature is not "a bad file appeared",
# it is a CHAIN: npm -> lifecycle hook -> sh -> curl. The shared features
# count binaries and depth but never say whose descendant a binary was, so
# a shell spawned by npm's own tooling and a shell spawned by a preinstall
# payload look identical. These encode the ancestry.
NPM_FEATURE_NAMES = [
    "n_exec_under_installer",   # execs whose parent is npm/node
    "n_foreign_under_installer",# non-npm/node binaries with an npm/node parent
    "has_shell_under_installer",
    "has_nettool_under_installer",
    "depth_first_foreign",      # how deep the first foreign binary sits
    "frac_first_foreign",       # where in the trace it appears
    "n_foreign_bins",           # distinct foreign binaries
    "max_foreign_chain",        # longest run of foreign ancestry
    # npm's CLI is itself a node program, so "node" has to be treated as
    # installer machinery -- which makes a `"preinstall": "node index.js"`
    # payload invisible to every foreign-binary feature above. Measured on
    # the collected corpus, an exec of node during install occurs in 21 of
    # 379 malicious traces and 0 of 1434 benign: 100% precision, 5.5%
    # recall. Rare, so it barely moves AUC, but it is never wrong.
    "n_node_exec",
    "n_node_exec_under_shell",
]

FEATURE_NAMES_NPM = FEATURE_NAMES + NPM_FEATURE_NAMES


def stat_dim():
    return len(FEATURE_NAMES_NPM) if _ecosystem() == "npm" else len(FEATURE_NAMES)


STAT_DIM = stat_dim()
