"""
ITBG - Install-Time Behavioral Graph.

Streams install events into a heterogeneous temporal graph and drives the
TGN encoder, which emits a 128-dim "DNA" vector after every event.

Node types (the old implementation had only Process and File):

    Process     - a running process, keyed by pid
    File        - a file path, bucketed by semantic role rather than by
                  literal path
    Network     - a connection destination (ip:port)
    Env         - environment/config reads
    Credential  - credential-bearing paths
    Script      - executed scripts and interpreters

Two design decisions worth stating, both learned from the previous version:

  1. Node identity is assigned per trace, in order of first appearance.
     Node ids therefore carry no global path vocabulary, so the model
     cannot memorize package names. This was already true before and is
     kept deliberately.

  2. File nodes are bucketed by ROLE, not by exact path. Keying on exact
     paths lets the graph encode sandbox-specific strings, which is how
     collection artifacts leak into a model. A path under site-packages
     is "package install target" regardless of which sandbox produced it.
"""

import torch

# Semantic buckets for file paths. Order matters: first match wins.
CREDENTIAL_HINTS = (
    "/.ssh/", "/.aws/", "/.netrc", "/.git-credentials", "/.pypirc",
    "/.npmrc", "/etc/shadow", "/.docker/config", "/.kube/config",
    "/.mozilla/", "/Login Data",
)
PERSISTENCE_HINTS = (
    "/.bashrc", "/.bash_profile", "/.zshrc", "/.profile", "/etc/cron",
    "/.ssh/authorized_keys", "/etc/systemd", "/.config/autostart",
)
SCRIPT_SUFFIXES = (".py", ".sh", ".pyc", ".so", ".pl", ".rb")

# Sandbox plumbing: constant per trace, independent of the package, and the
# source of the /dev/pts artifact that broke the previous model. Dropped
# before the graph ever sees it.
BOOTSTRAP_HINTS = (
    "/dev/pts", "/dev/tty", "/dev/ptmx", "/dev/null", "/etc/passwd",
    "/etc/group", "/etc/login.defs", "/etc/nsswitch.conf", "/etc/pam.d/",
    "/etc/security/", "/run/systemd/userdb/", "/etc/ld.so.cache",
    ".pyenv/", "/pip-install-", "/pip-ephem-wheel-cache-", "/pip-req-build-",
    "/pip-unpack-", "/pip-metadata-", "__pycache__", ".dist-info",
)

NODE_KINDS = ("process", "file", "network", "env", "credential", "script")
EDGE_TYPES = {"exec": 0.0, "open": 1.0, "write": 2.0, "connect": 3.0,
              "credential_read": 4.0, "env_read": 5.0}


# Coarse path buckets. A node's identity is its ROLE, not its literal path and
# not its position in the event stream.
PATH_BUCKETS = (
    ("credential", CREDENTIAL_HINTS),
    ("persistence", PERSISTENCE_HINTS),
    ("site_packages", ("site-packages", "dist-packages")),
    ("tmp", ("/tmp/", "/var/tmp/")),
    ("home", ("/home/", "/root/")),
    ("etc", ("/etc/",)),
    ("usr", ("/usr/", "/lib/", "/bin/", "/sbin/")),
    ("proc", ("/proc/", "/sys/")),
    ("dev", ("/dev/",)),
)


def path_bucket(path: str) -> str:
    for name, hints in PATH_BUCKETS:
        if any(h in path for h in hints):
            return name
    return "other"


class NodeIDMap:
    """Semantic node ids, stable across captures.

    Identity used to be the order of first appearance. That made the whole
    representation fragile: one extra or missing event early in a trace shifted
    every subsequent id, so the TGN memory evolved over a different indexing and
    two captures of the SAME package could score 0.98 and 0.006. Measured
    directly on rdquests-2.28.1, whose two captures differ by a single event.

    Identity is now derived from what a node IS -- a process by its executable
    name, a file by its role bucket and depth, a destination by whether it is
    external and its port class. Two captures of the same install therefore
    produce the same node ids.

    This still cannot memorise package names: buckets are coarse categories,
    never literal paths, so nothing package-specific enters the identity.
    """

    def __init__(self, num_nodes=50000):
        self.num_nodes = num_nodes
        self.map = {}
        self.kinds = {}

    def get(self, key, kind):
        if key not in self.map:
            # Stable hash -> fixed id space. Python's hash() is randomised per
            # process, so a deterministic digest is required.
            import hashlib
            h = int(hashlib.md5(f"{kind}:{key}".encode()).hexdigest()[:8], 16)
            self.map[key] = h % self.num_nodes
            self.kinds[self.map[key]] = kind
        return self.map[key]

    def __len__(self):
        return len(self.map)


def is_bootstrap(path: str) -> bool:
    return bool(path) and any(h in path for h in BOOTSTRAP_HINTS)


def classify_path(path: str) -> str:
    """Bucket a path into a node kind."""
    if any(h in path for h in CREDENTIAL_HINTS):
        return "credential"
    if path.endswith(SCRIPT_SUFFIXES):
        return "script"
    if path.startswith("/etc/") or path.endswith((".cfg", ".ini", ".toml", ".json", ".yaml")):
        return "env"
    return "file"


class ITBGConstructor:
    """Streams events into the TGN, emitting a DNA vector per event."""

    def __init__(self, tgn_encoder, edge_feat_dim=32):
        self.tgn = tgn_encoder
        self.edge_feat_dim = edge_feat_dim
        self.reset()

    def reset(self):
        # The TGN memory dict holds tensors that are part of the autograd
        # graph. Without clearing it between traces, trace N+1 keeps
        # references into trace N's graph, and the second backward() in a
        # batch dies with "Trying to backward through the graph a second
        # time". Memory is per-install-session by design anyway.
        self.tgn.memory_bank.reset_memory()
        self.node_ids = NodeIDMap()
        self.dna_history = []
        self.last_dna = None

    # ------------------------------------------------------------------
    def _edge_features(self, event, etype: str, path: str):
        """Behavioral edge attributes. These encode WHAT HAPPENED, never
        which sandbox it happened in."""
        is_write = float(bool(event.get("write")))
        is_cred = float(any(h in path for h in CREDENTIAL_HINTS))
        is_persist = float(any(h in path for h in PERSISTENCE_HINTS))
        is_tmp = float(path.startswith("/tmp") or path.startswith("/var/tmp"))
        is_sp = float("site-packages" in path)
        is_home = float("/home/" in path or path.startswith("/root/"))
        is_hidden = float("/." in path)
        is_script = float(path.endswith(SCRIPT_SUFFIXES))

        dport = event.get("dport") or 0
        daddr = event.get("daddr") or ""
        is_ext = float(bool(daddr) and not (
            daddr.startswith("127.") or daddr.startswith("10.")
            or daddr.startswith("192.168.")))
        is_nonstd_port = float(dport not in (0, 80, 443))

        comm = (event.get("comm") or "").rsplit("/", 1)[-1]
        is_shell = float(comm in ("sh", "bash", "zsh", "dash", "ksh"))
        is_nettool = float(comm in ("curl", "wget", "nc", "ncat", "dig"))

        base = torch.tensor([
            EDGE_TYPES.get(etype, -1.0), is_write, is_cred, is_persist,
            is_tmp, is_sp, is_home, is_hidden, is_script,
            is_ext, is_nonstd_port, is_shell, is_nettool,
            min(len(path) / 200.0, 1.0), min(path.count("/") / 20.0, 1.0),
        ], dtype=torch.float32)

        reps = (self.edge_feat_dim // base.shape[0]) + 1
        return base.repeat(reps)[: self.edge_feat_dim]

    # ------------------------------------------------------------------
    def add_event(self, event):
        etype = event.get("type", "")
        path = event.get("fname", "") or ""

        if is_bootstrap(path):
            return None

        pid = event.get("pid", 0)
        ppid = event.get("ppid", 0)

        # Processes are identified by executable name, not PID: PIDs differ
        # between runs of the same install and carry no behavioural meaning.
        comm = (event.get("comm") or "?").rsplit("/", 1)[-1]

        if etype == "exec":
            src = self.node_ids.get(f"proc:{comm}", "process")
            target = (path or comm).rsplit("/", 1)[-1]
            kind = "script" if path.endswith(SCRIPT_SUFFIXES) else "process"
            dst = self.node_ids.get(f"proc:{target}", kind)

        elif etype == "connect":
            src = self.node_ids.get(f"proc:{comm}", "process")
            daddr = event.get("daddr") or ""
            dport = event.get("dport") or 0
            # Identity is "what kind of destination", not which IP -- addresses
            # rotate between captures (CDN load balancing) and would otherwise
            # make every run look different.
            ext = bool(daddr) and not daddr.startswith(("127.", "10.", "192.168."))
            pclass = "std" if dport in (80, 443, 53) else "nonstd"
            dst = self.node_ids.get(f"net:{'ext' if ext else 'local'}:{pclass}", "network")

        elif etype == "open":
            if not path:
                return None
            src = self.node_ids.get(f"proc:{comm}", "process")
            kind = classify_path(path)
            # Role bucket plus depth: coarse enough to be identical across
            # captures, fine enough to separate a site-packages write from a
            # credential read.
            # Identity must be stable across captures but still fine-grained:
            # collapsing to the bucket alone left only ~47 nodes and cost 13
            # points of recall. Directory structure and file type are stable
            # properties of an install (they do not shift when one event is
            # missing), so they are safe to include. The package's own name is
            # still excluded -- only the last TWO path components are used, and
            # the leaf is reduced to its extension.
            parts = [c for c in path.split("/") if c]
            parent = parts[-2] if len(parts) >= 2 else ""
            ext = ("." + parts[-1].rsplit(".", 1)[-1]) if (parts and "." in parts[-1]) else "noext"
            depth = min(path.count("/"), 10)
            dst = self.node_ids.get(
                f"{kind}:{path_bucket(path)}:{parent}:{ext}:{depth}", kind)
            if kind == "credential":
                etype = "credential_read"
            elif kind == "env":
                etype = "env_read"
            elif event.get("write"):
                etype = "write"
        else:
            return None

        edge_feat = self._edge_features(event, etype, path)
        t = torch.tensor(float(event.get("ts", 0)))
        dna = self.tgn.step(src, dst, t, edge_feat)

        self.dna_history.append(dna.detach())
        self.last_dna = dna
        return dna

    # ------------------------------------------------------------------
    def replay(self, events, snapshots=(0.25, 0.50, 0.75, 1.00)):
        """Replay a full trace, returning DNA snapshots at fixed relative
        checkpoints. Every event updates memory; only the snapshots are
        returned, so traces of very different lengths stay comparable."""
        self.reset()
        n = len(events)
        if n == 0:
            return None

        marks = {max(0, int(n * frac) - 1) for frac in snapshots}
        out = []
        for i, e in enumerate(events):
            dna = self.add_event(e)
            if i in marks:
                out.append(dna if dna is not None else self.last_dna)

        out = [d for d in out if d is not None]
        if not out:
            return None
        while len(out) < len(snapshots):
            out.append(out[-1])
        return torch.stack(out[: len(snapshots)])
