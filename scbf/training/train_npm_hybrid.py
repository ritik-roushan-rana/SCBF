"""
SCBF - NPM Hybrid Model V1

Trains the Hybrid V2 architecture (TGN encoder + statistical feature
encoder + residual fusion classifier, see train_hybrid_v2.py) on the RQ1
NPM behavioral dataset.

Dataset:
    data/rq1_npm/benign/traces/*.jsonl    (~1474 benign installs)
    data/rq1_npm/malware/traces/*.jsonl   (~482 malicious installs)

Differences from the PyPI trainer (train_hybrid_v2.py):

  * Path canonicalization at load time. The raw traces contain the
    dataset directory in the tarball path
    (/home/user/rq1_npm_benign/... vs /home/user/rq1_npm_malware/...),
    per-session cgroup UUIDs, /tmp/scbf-npm-install-<pid> and similar
    volatile strings. Without canonicalization a model can read the label
    straight off the path. Every path is rewritten to a stable form at
    both training and inference time.

  * NPM-specific statistical features on top of the 45 PyPI features
    (node_modules structure, npm cache activity, lifecycle-script process
    activity, recon commands, credential/system file access, network
    timing, ...). The stat encoder is the same architecture with a wider
    input layer.

  * Dataset-level feature standardisation (mean/std fitted on the training
    split and stored inside the checkpoint) instead of per-sample
    standardisation.

  * Fast, faithful TGN replay: identical maths to ITBGConstructor.
    replay_session but with the per-event Python overhead removed and the
    projection head only evaluated at the 25/50/75/100% snapshots. Long
    traces are uniformly strided down to MAX_TGN_EVENTS for the TGN
    branch (the statistical branch always sees the full trace).

  * Parallel data-parallel training on CPU (a worker pool computes
    gradients for shards of every mini-batch; the main process sums them
    and steps a single optimizer).

IMPORTANT:
    This script DOES NOT overwrite the PyPI model models/scbf_hybrid_v2.pt.
    The NPM model is saved as models/scbf_npm_hybrid_v1.pt

Usage:
    python -m scbf.training.train_npm_hybrid
    python -m scbf.training.train_npm_hybrid --workers 8 --epochs 60
"""

import argparse
import glob
import json
import os
import random
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.multiprocessing as mp
import torch.nn as nn
import torch.nn.functional as F

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from scbf.models.itbg_constructor import ITBGConstructor, NodeIDMap, SNAPSHOT_FRACTIONS  # noqa: E402
from scbf.training.train_hybrid_v2 import HybridClassifierV2, extract_features_v2  # noqa: E402
from scbf.training.npm_rich_features import RICH_FEATURE_DIM, extract_rich_features  # noqa: E402


# ============================================================
# 0. CONSTANTS
# ============================================================

DATA_DIR = "data/rq1_npm"          # overridable with --data-dir (e.g. data/rq1_npm_rich)
BENIGN_GLOB = f"{DATA_DIR}/benign/traces/*.jsonl"
MALWARE_GLOB = f"{DATA_DIR}/malware/traces/*.jsonl"

MODEL_OUTPUT = PROJECT_ROOT / "models" / "scbf_npm_hybrid_v1.pt"
CHECKPOINT_DIR = PROJECT_ROOT / "models" / "checkpoints_npm"
CACHE_FILE = CHECKPOINT_DIR / "npm_preprocessed_cache.pt"
CACHE_FILE_RICH = CHECKPOINT_DIR / "npm_preprocessed_cache_rich.pt"

# Rich features (exec argv, connect destination, install/require phase) need
# traces captured with the extended telemetry described in
# npm_rich_features.py. Enabled with --rich; the checkpoint remembers it.
USE_RICH = False
RESULTS_FILE = PROJECT_ROOT / "models" / "npm_evaluation_results.json"
SPLIT_FILE = CHECKPOINT_DIR / "split_info.json"
INERT_FILE = PROJECT_ROOT / "data" / "rq1_npm" / "install_inert.json"

# Maximum number of events replayed through the TGN per trace. Traces
# longer than this are uniformly strided (the payload of an install script
# can be anywhere in the stream, so we never truncate).
MAX_TGN_EVENTS = 1500


# ============================================================
# 1. PATH CANONICALIZATION
# ============================================================

# Order matters: the dataset rule must run before the generic /home rule.
_DATASET_RE = re.compile(r"/home/[^/]+/rq1_npm_(?:benign|malware)(?:/npm_malware)?/")
_HOME_RE = re.compile(r"/home/[^/]+")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_TMPNUM_RE = re.compile(r"(/tmp/scbf-npm-(?:install|cache|pkg))-[A-Za-z0-9_]+")
_PTS_RE = re.compile(r"/dev/pts/\d+")
_PROC_RE = re.compile(r"/proc/\d+")
_PYVER_RE = re.compile(r"python3\.\d+")
_NPMLOG_RE = re.compile(r"/_logs/[^/]+-debug-\d+\.log")


def canonicalize_path(path):
    """Rewrite volatile / label-leaking parts of a path to stable placeholders."""
    if not path:
        return path
    p = _DATASET_RE.sub("<dataset>/", path)
    p = _HOME_RE.sub("<home>", p)
    p = _UUID_RE.sub("<uuid>", p)
    p = _TMPNUM_RE.sub(r"\1", p)
    p = _PTS_RE.sub("/dev/pts/N", p)
    p = _PROC_RE.sub("/proc/N", p)
    p = _PYVER_RE.sub("python3.X", p)
    p = _NPMLOG_RE.sub("/_logs/<npm-debug-log>", p)
    return p


def load_events(path):
    """Load a JSONL trace and canonicalize every fname."""
    events = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            e["fname"] = canonicalize_path(e.get("fname", ""))
            events.append(e)
    return events


# ============================================================
# 2. FEATURE EXTRACTION
# ============================================================

# Commands whose presence / count carries signal on npm installs.
NPM_COMMS = [
    "curl", "wget", "nc", "ncat", "netcat", "bash", "sh", "dash", "zsh",
    "python", "python3", "perl", "ruby", "chmod", "chown", "base64",
    "openssl", "find", "ls", "cat", "whoami", "id", "uname", "hostname",
    "ifconfig", "ip", "env", "printenv", "tar", "gzip", "unzip", "git",
    "make", "gcc", "cc1", "cc1plus", "node", "npm", "npx", "yarn", "sudo",
    "ping", "nslookup", "dig", "ssh", "scp", "xxd", "echo", "grep", "awk",
    "sed", "head", "tail", "sleep", "crontab", "systemctl", "kill", "ps",
    "df", "free", "mount", "rm", "mv", "cp", "mkdir", "touch", "which",
    "chattr",
]

# Path substrings (on canonicalized paths) counted per trace.
NPM_PATH_PATTERNS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
    "/etc/os-release", "/etc/machine-id", "/etc/resolv.conf", ".ssh",
    ".aws", ".npmrc", ".gitconfig", ".bash_history", ".env", "/.config/",
    "package.json", "package-lock.json", "node_modules", ".bin/", "/tmp/",
    "/var/tmp/", "/dev/shm", "/proc/self/", "/proc/N/", "/proc/cpuinfo",
    "/proc/meminfo", "/proc/net", "/sys/class/net", "/sys/devices",
    "/sys/fs/cgroup", "/dev/urandom", "/dev/null", "/dev/tcp", "/usr/bin/",
    "/usr/share/nodejs", "/usr/share/node_modules", "/usr/lib/python3",
    "/usr/lib/node_modules", "_cacache", "<home>/.npm", "<home>/.cache",
    "<home>/", "<dataset>", "/.git/", "/lib/x86_64", "/etc/ssl",
    "/usr/lib/ssl", "/etc/ld.so", "/run/systemd", "/etc/pam.d",
    "/var/lib/sss", "/etc/security", "/dev/pts", "preinstall",
    "postinstall", "install.js", "index.js", ".sh", ".py", ".tgz", ".tar",
    ".zip", ".gz", ".so", ".node", ".json", ".md", ".ts", ".mjs", ".cjs",
    ".txt", ".yml", ".yaml", ".lock", ".log", "LICENSE",
]

# Comms whose share of the event stream is a feature.
NPM_SHARE_COMMS = [
    "libuv-worker", "npm", "node", "sudo", "cc1", "cc1plus", "python3",
    "find", "sh", "bash", "git", "make", "node-gyp", "unzip", "ls", "curl",
]

# Comms that npm itself uses for network access. Connects from anything
# else are counted separately as "foreign" connects.
_NPM_NET_COMMS = {"npm", "node", "libuv-worker", "git-remote-http", "sudo"}


def extract_features_npm(events, rich=None):
    """45 PyPI features + NPM-specific features (+ rich telemetry features
    when `rich`, default USE_RICH). Events must be canonicalized."""
    base = extract_features_v2(events)
    feats = list(base)
    n = len(events)

    comms = [e.get("comm", "") for e in events]
    comm_counts = Counter(c.lower().strip() for c in comms)
    for c in NPM_COMMS:
        feats.append(np.log1p(comm_counts.get(c, 0)))

    paths = [e["fname"] for e in events if e.get("fname")]
    for pat in NPM_PATH_PATTERNS:
        k = sum(1 for p in paths if pat in p)
        feats.append(np.log1p(k))
        feats.append(k / max(1, n))

    # node_modules structure: distinct packages touched and nesting depth
    packages = set()
    depths = []
    for p in paths:
        i = p.find("/node_modules/")
        if i != -1:
            rest = p[i + len("/node_modules/"):].split("/")
            if rest and rest[0]:
                packages.add("/".join(rest[:2]) if rest[0].startswith("@") else rest[0])
            depths.append(p.count("/node_modules/"))
    feats.append(np.log1p(len(packages)))
    feats.append(max(depths, default=0))
    feats.append(float(np.mean(depths)) if depths else 0.0)

    # process tree shape
    execs = [e for e in events if e.get("type") == "exec"]
    feats.append(np.log1p(len(execs)))
    feats.append(len(set(e.get("comm") for e in execs)))
    pids = set(e.get("pid") for e in events)
    ppids = set(e.get("ppid") for e in events)
    feats.append(np.log1p(len(pids)))
    feats.append(np.log1p(len(ppids)))
    feats.append(len(pids - ppids) / max(1, len(pids)))

    # network activity broken down by originating process
    cons = [e for e in events if e.get("type") == "connect"]
    feats.append(np.log1p(len(cons)))
    feats.append(len(set(e.get("pid") for e in cons)))
    feats.append(sum(1 for e in cons if e.get("comm", "").lower() not in _NPM_NET_COMMS))
    feats.append(sum(1 for e in cons if e.get("comm", "").lower() == "node"))
    feats.append(sum(1 for e in cons if e.get("comm", "").lower() == "npm"))

    # where in the install the network activity happens
    if cons and n > 1:
        ts = sorted(e["ts"] for e in events)
        t0, t1 = ts[0], ts[-1]
        d = max(1, t1 - t0)
        cts = sorted(e["ts"] for e in cons)
        feats.append((cts[0] - t0) / d)
        feats.append((cts[-1] - t0) / d)
        feats.append(np.log1p((cts[-1] - cts[0]) / 1e6))
    else:
        feats.extend([0.0, 0.0, 0.0])

    for c in NPM_SHARE_COMMS:
        feats.append(comm_counts.get(c, 0) / max(1, n))

    # directory diversity
    dirs = Counter("/".join(p.split("/")[:3]) for p in paths)
    total = sum(dirs.values()) or 1
    feats.append(-sum(v / total * np.log(v / total) for v in dirs.values()))
    feats.append(len(dirs))
    feats.append(len(set(paths)) / max(1, len(paths)))
    feats.append(np.log1p(max(Counter(paths).values(), default=0)))

    if USE_RICH if rich is None else rich:
        feats.extend(extract_rich_features(events))

    out = np.nan_to_num(np.array(feats, dtype=np.float32))
    return out


NPM_FEATURE_DIM = len(extract_features_npm(
    [{"type": "open", "pid": 1, "ppid": 0, "comm": "npm", "fname": "/x", "ts": 1}], rich=False
))


def feature_dim(rich=None):
    return NPM_FEATURE_DIM + (RICH_FEATURE_DIM if (USE_RICH if rich is None else rich) else 0)


def cache_file(rich=None):
    return CACHE_FILE_RICH if (USE_RICH if rich is None else rich) else CACHE_FILE


# ============================================================
# 3. TGN INPUT PRE-COMPUTATION + FAST REPLAY
# ============================================================

def subsample_events(events, max_events=MAX_TGN_EVENTS):
    """Sort by ts and uniformly stride down to at most max_events."""
    events = sorted(events, key=lambda x: x["ts"])
    if len(events) <= max_events:
        return events
    idx = np.linspace(0, len(events) - 1, max_events).round().astype(int)
    return [events[i] for i in idx]


def tgn_inputs_from_events(events, max_events=MAX_TGN_EVENTS):
    """Turn a (canonicalized) event list into the tensors the TGN needs.

    Mirrors ITBGConstructor.add_event / replay_session exactly: same noise
    filter, same node-id assignment, same edge features, same snapshot
    indices. Returns None if nothing survives the noise filter.
    """
    events = subsample_events(events, max_events)
    total = len(events)
    if total == 0:
        return None

    helper = ITBGConstructor(tgn_encoder=None)
    ids = NodeIDMap()
    checkpoints = {int(total * f) - 1 for f in SNAPSHOT_FRACTIONS if int(total * f) > 0}
    checkpoints.add(total - 1)

    src, dst, feats, ts, snap = [], [], [], [], []
    for i, e in enumerate(events):
        if helper._is_noise(e):
            continue
        if e["type"] == "exec":
            s = ids.get(f"proc:{e.get('ppid', 0)}")
            d = ids.get(f"proc:{e.get('pid', 0)}")
        elif e["type"] == "open":
            s = ids.get(f"proc:{e.get('pid', 0)}")
            d = ids.get(f"file:{e.get('fname', '')}")
        else:
            continue
        src.append(s)
        dst.append(d)
        feats.append(helper._edge_features(e))
        ts.append(float(e["ts"]))
        snap.append(i in checkpoints)

    if not src:
        return None

    return {
        "src": np.array(src, dtype=np.int64),
        "dst": np.array(dst, dtype=np.int64),
        "feats": torch.stack(feats),                      # [E, 32]
        "ts": torch.tensor(ts, dtype=torch.float32),      # [E]
        "snap": np.array(snap, dtype=bool),
    }


def replay_tgn(tgn, inputs):
    """Sequential TGN memory replay over precomputed inputs.

    Numerically identical to ITBGConstructor.replay_session (verified),
    but the projection head is only applied at snapshot events.
    """
    mb = tgn.memory_bank
    mem, last = {}, {}
    zero = torch.zeros(mb.memory_dim)
    t_zero = torch.tensor(0.0)
    feats, ts = inputs["feats"], inputs["ts"]
    src, dst, snap = inputs["src"], inputs["dst"], inputs["snap"]

    snapshots = []
    last_mem = None
    for j in range(len(src)):
        s, d = int(src[j]), int(dst[j])
        mem_src = mem.get(s, zero)
        last_src = last.get(s, t_zero)
        if s not in mem:
            mem[s] = zero
            last[s] = t_zero
        t_enc = mb.time_encoder((ts[j] - last_src).unsqueeze(0)).squeeze(0)
        msg = torch.cat([mem_src, feats[j], t_enc], dim=-1)
        mem_dst = mem.get(d, zero)
        new_mem = mb.gru(msg.unsqueeze(0), mem_dst.unsqueeze(0)).squeeze(0)
        mem[d] = new_mem
        last[d] = ts[j]
        last_mem = new_mem
        if snap[j]:
            snapshots.append(new_mem)

    if not snapshots:
        snapshots = [last_mem]
    dnas = [F.normalize(tgn.proj(m), dim=-1) for m in snapshots]
    return torch.stack(dnas).mean(dim=0)


# ============================================================
# 4. MODEL
# ============================================================

class NPMHybridClassifier(HybridClassifierV2):
    """Hybrid V2 architecture with the NPM feature set.

    Same TGN encoder, stat encoder, and residual fusion head as
    HybridClassifierV2; only the stat-encoder input width and the feature
    normalisation differ (dataset-level z-scoring, stored as buffers so the
    checkpoint is self-contained).
    """

    def __init__(self, num_nodes=50000, embedding_dim=128, stat_dim=NPM_FEATURE_DIM):
        super().__init__(num_nodes=num_nodes, embedding_dim=embedding_dim, stat_dim=stat_dim)
        self.register_buffer("feat_mean", torch.zeros(stat_dim))
        self.register_buffer("feat_std", torch.ones(stat_dim))
        self.register_buffer("threshold", torch.tensor(0.5))

    @staticmethod
    def _squash(x):
        return torch.log1p(torch.abs(x)) * torch.sign(x)

    def fit_normalizer(self, feature_matrix):
        """Fit mean/std of the squashed features on the TRAINING split only."""
        x = self._squash(torch.as_tensor(feature_matrix, dtype=torch.float32))
        self.feat_mean.copy_(x.mean(dim=0))
        self.feat_std.copy_(x.std(dim=0) + 1e-6)

    def head(self, tgn_emb, stat_features):
        stat = torch.as_tensor(stat_features, dtype=torch.float32)
        stat = (self._squash(stat) - self.feat_mean) / self.feat_std
        stat_emb = self.stat_encoder(stat)
        combined = torch.cat([tgn_emb, stat_emb], dim=-1)

        h1 = F.gelu(self.ln1(self.fc1(combined)))
        h1 = self.dropout1(h1)
        h2 = F.gelu(self.ln2(self.fc2(h1)))
        h2 = self.dropout2(h2)
        h2 = h2 + h1
        h3 = F.gelu(self.ln3(self.fc3(h2)))
        h3 = self.dropout3(h3)
        return combined, self.fc_out(h3)

    def forward_cached(self, sample):
        """Forward from a preprocessed sample dict (training / evaluation)."""
        if sample["tgn"] is None:
            return None, None
        tgn_emb = replay_tgn(self.tgn, sample["tgn"])
        return self.head(tgn_emb, sample["feats"])

    @property
    def uses_rich_features(self):
        return self.feat_mean.numel() > NPM_FEATURE_DIM

    def forward(self, events):
        """Forward from a raw event list (inference). Events are canonicalized here.
        The feature set (base / rich) is inferred from the checkpoint's stat_dim."""
        events = [dict(e, fname=canonicalize_path(e.get("fname", ""))) for e in events]
        tgn_inputs = tgn_inputs_from_events(events)
        if tgn_inputs is None:
            return None, None
        tgn_emb = replay_tgn(self.tgn, tgn_inputs)
        return self.head(tgn_emb, extract_features_npm(events, rich=self.uses_rich_features))


# ============================================================
# 5. LOSS
# ============================================================

class FocalBCELoss(nn.Module):
    def __init__(self, pos_weight=1.0, gamma=2.0):
        super().__init__()
        self.pos_weight = torch.tensor(float(pos_weight))
        self.gamma = gamma

    def forward(self, logits, targets):
        bce = F.binary_cross_entropy_with_logits(
            logits, targets, pos_weight=self.pos_weight, reduction="none"
        )
        p = torch.sigmoid(logits)
        p_t = p * targets + (1 - p) * (1 - targets)
        return ((1 - p_t) ** self.gamma * bce).mean()


# ============================================================
# 6. DATA
# ============================================================

def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def discover_traces(exclude_inert=False, data_dir=DATA_DIR):
    benign = sorted(glob.glob(str(PROJECT_ROOT / data_dir / "benign" / "traces" / "*.jsonl")))
    malware = sorted(glob.glob(str(PROJECT_ROOT / data_dir / "malware" / "traces" / "*.jsonl")))
    if exclude_inert:
        # Malware whose payload never ran during `npm install` (see
        # find_inert_npm.py). Behaviorally identical to a benign install,
        # so it is label noise for an install-time detector.
        inert_file = PROJECT_ROOT / data_dir / "install_inert.json"
        if not inert_file.exists():
            raise RuntimeError(f"{inert_file} not found - run: python -m scbf.training.find_inert_npm {data_dir}")
        inert = set(json.load(open(inert_file))["malware"]["inert"])
        before = len(malware)
        malware = [p for p in malware if os.path.basename(p) not in inert]
        print(f"  Excluded {before - len(malware)} install-inert malware traces")
    return benign, malware


def _preprocess_init(rich):
    global USE_RICH
    USE_RICH = rich
    torch.set_num_threads(1)


def _preprocess_one(path):
    """Worker: load + canonicalize a trace, compute stat features and TGN inputs."""
    try:
        events = load_events(path)
        if not events:
            return path, None, "empty"
        required = {"type", "pid", "ppid", "comm", "fname", "ts"}
        if any(not required.issubset(e) for e in events):
            return path, None, "missing_fields"
        return path, {
            "feats": extract_features_npm(events),
            "tgn": tgn_inputs_from_events(events),
            "n_events": len(events),
        }, None
    except Exception as e:  # noqa: BLE001
        return path, None, repr(e)


def build_cache(paths, workers):
    """Preprocess every trace once (parallel) and cache the result on disk.

    The cache is keyed by (path, mtime, size) so edited/added traces are
    recomputed automatically.
    """
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    cache = {}
    if cache_file().exists():
        try:
            cache = torch.load(cache_file(), map_location="cpu", weights_only=False)
            if cache.get("_meta", {}).get("feature_dim") != feature_dim() \
                    or cache.get("_meta", {}).get("max_tgn_events") != MAX_TGN_EVENTS:
                print("  Cache built with a different feature set -> rebuilding.")
                cache = {}
        except Exception:  # noqa: BLE001
            cache = {}

    def key(p):
        st = os.stat(p)
        return f"{p}|{int(st.st_mtime)}|{st.st_size}"

    todo = [p for p in paths if key(p) not in cache]
    print(f"  Cached: {len(paths) - len(todo)}   To preprocess: {len(todo)}")

    failures = []
    if todo:
        t0 = time.time()
        results = []
        if workers > 1:
            with mp.get_context("spawn").Pool(workers, initializer=_preprocess_init, initargs=(USE_RICH,)) as pool:
                for i, r in enumerate(pool.imap_unordered(_preprocess_one, todo, chunksize=4), 1):
                    results.append(r)
                    if i % 100 == 0 or i == len(todo):
                        print(f"    preprocessed {i}/{len(todo)}  ({time.time() - t0:.0f}s)")
        else:
            for i, p in enumerate(todo, 1):
                results.append(_preprocess_one(p))
                if i % 100 == 0 or i == len(todo):
                    print(f"    preprocessed {i}/{len(todo)}  ({time.time() - t0:.0f}s)")
        for path, sample, err in results:
            if sample is None:
                failures.append((path, err))
            else:
                cache[key(path)] = sample
        cache["_meta"] = {"feature_dim": feature_dim(), "max_tgn_events": MAX_TGN_EVENTS, "rich": USE_RICH}
        torch.save(cache, cache_file())
        print(f"  Cache saved -> {cache_file()}")

    samples = {p: cache[key(p)] for p in paths if key(p) in cache}
    return samples, failures


def split_data(clean_paths, mal_paths, train_ratio=0.70, val_ratio=0.15, seed=42):
    set_seed(seed)
    clean, malware = clean_paths.copy(), mal_paths.copy()
    random.shuffle(clean)
    random.shuffle(malware)

    def cut(lst):
        a = int(len(lst) * train_ratio)
        b = int(len(lst) * (train_ratio + val_ratio))
        return lst[:a], lst[a:b], lst[b:]

    c_tr, c_va, c_te = cut(clean)
    m_tr, m_va, m_te = cut(malware)
    train = [(p, 0) for p in c_tr] + [(p, 1) for p in m_tr]
    val = [(p, 0) for p in c_va] + [(p, 1) for p in m_va]
    test = [(p, 0) for p in c_te] + [(p, 1) for p in m_te]
    for s in (train, val, test):
        random.shuffle(s)
    return train, val, test


# ============================================================
# 7. METRICS
# ============================================================

def compute_metrics(logits, labels, threshold=0.5):
    probs = torch.sigmoid(logits)
    pred = (probs > threshold).long()
    lab = labels.long()
    tp = int(((pred == 1) & (lab == 1)).sum())
    tn = int(((pred == 0) & (lab == 0)).sum())
    fp = int(((pred == 1) & (lab == 0)).sum())
    fn = int(((pred == 0) & (lab == 1)).sum())
    total = len(labels)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "auc": roc_auc(probs, labels),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    }


def roc_auc(probs, labels):
    """Rank-based AUC (no sklearn dependency)."""
    p = probs.detach().numpy()
    y = labels.detach().numpy()
    n_pos, n_neg = (y == 1).sum(), (y == 0).sum()
    if n_pos == 0 or n_neg == 0:
        return 0.0
    order = np.argsort(p)
    ranks = np.empty(len(p))
    ranks[order] = np.arange(1, len(p) + 1)
    # average ranks for ties
    _, inv, counts = np.unique(p, return_inverse=True, return_counts=True)
    sums = np.bincount(inv, weights=ranks)
    ranks = (sums / counts)[inv]
    return float((ranks[y == 1].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def fmt(m):
    return (f"acc={m['accuracy']:.2%} P={m['precision']:.2%} R={m['recall']:.2%} "
            f"F1={m['f1']:.2%} FPR={m['fpr']:.2%} AUC={m['auc']:.4f}")


# ============================================================
# 8. WORKER POOL (data-parallel gradient computation on CPU)
# ============================================================

_W = {}  # per-worker globals


def _worker_init(samples, labels, num_nodes, stat_dim, pos_weight, gamma):
    torch.set_num_threads(1)
    _W["samples"] = samples
    _W["labels"] = labels
    _W["model"] = NPMHybridClassifier(num_nodes=num_nodes, stat_dim=stat_dim)
    _W["loss_fn"] = FocalBCELoss(pos_weight=pos_weight, gamma=gamma)


def _worker_grads(args):
    """Compute summed loss gradient for a shard of a mini-batch.

    Returns per-parameter gradients of (sum of per-sample focal losses), the
    summed loss and the number of successful samples so the main process can
    average across shards exactly as a single-process batch would.
    """
    state, indices = args
    model, loss_fn = _W["model"], _W["loss_fn"]
    model.load_state_dict(state)
    model.train()
    logits, targets = [], []
    for i in indices:
        _, lg = model.forward_cached(_W["samples"][i])
        if lg is None:
            continue
        logits.append(lg.squeeze())
        targets.append(float(_W["labels"][i]))
    if not logits:
        return None, 0.0, 0
    logits = torch.stack(logits)
    targets = torch.tensor(targets)
    # loss_fn averages; multiply back to a sum so shards can be combined
    loss = loss_fn(logits, targets) * len(logits)
    model.zero_grad()
    loss.backward()
    grads = [(p.grad.detach().clone() if p.grad is not None else None) for p in model.parameters()]
    return grads, float(loss.detach()), len(logits)


def _worker_eval(args):
    state, indices = args
    model = _W["model"]
    model.load_state_dict(state)
    model.eval()
    out = []
    with torch.no_grad():
        for i in indices:
            _, lg = model.forward_cached(_W["samples"][i])
            if lg is not None:
                out.append((i, float(lg.squeeze())))
    return out


def _shards(indices, n):
    n = max(1, min(n, len(indices)))
    return [indices[i::n] for i in range(n)]


def _cpu_state(model):
    return {k: v.detach().clone() for k, v in model.state_dict().items()}


def run_eval(pool, model, indices, workers):
    """Logits for the given sample indices, in index order."""
    state = _cpu_state(model)
    if pool is None:
        results = [_worker_eval((state, indices))]
    else:
        results = pool.map(_worker_eval, [(state, s) for s in _shards(indices, workers)])
    got = dict(r for chunk in results for r in chunk)
    kept = [i for i in indices if i in got]
    logits = torch.tensor([got[i] for i in kept])
    return logits, kept


# ============================================================
# 9. MAIN
# ============================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=max(1, min(12, (os.cpu_count() or 2) - 2)))
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--patience", type=int, default=15)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--weight-decay", type=float, default=1e-3)
    ap.add_argument("--gamma", type=float, default=2.0)
    ap.add_argument("--seed", type=int, default=42, help="model init / shuffle seed")
    ap.add_argument("--split-seed", type=int, default=42, help="train/val/test split seed (keep fixed across runs)")
    ap.add_argument("--tag", default="", help="suffix for checkpoint/model names (for multi-seed ensembles)")
    ap.add_argument("--data-dir", default=DATA_DIR,
                    help="dataset root containing benign/traces and malware/traces (default data/rq1_npm)")
    ap.add_argument("--rich", action="store_true",
                    help="use rich telemetry features (exec argv / connect dst / phase); see npm_rich_features.py")
    ap.add_argument("--exclude-inert", action="store_true",
                    help="drop malware traces whose payload never ran at install time (data/rq1_npm/install_inert.json)")
    ap.add_argument("--num-nodes", type=int, default=50000)
    args = ap.parse_args()

    global USE_RICH
    USE_RICH = args.rich
    set_seed(args.seed)
    torch.set_num_threads(1)
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("SCBF NPM HYBRID MODEL TRAINING")
    print("=" * 80)
    print(f"Feature dim     : {feature_dim()}"
          + (f"  (base {NPM_FEATURE_DIM} + rich {RICH_FEATURE_DIM})" if USE_RICH else ""))
    print(f"TGN events cap  : {MAX_TGN_EVENTS}")
    print(f"Workers         : {args.workers}")

    # ---------------- data ----------------
    benign, malware = discover_traces(exclude_inert=args.exclude_inert, data_dir=args.data_dir)
    print(f"\nDataset:\n  Benign traces   : {len(benign)}\n  Malware traces  : {len(malware)}")
    if not benign or not malware:
        raise RuntimeError(f"Dataset not found under {args.data_dir}/ (need benign/traces and malware/traces)")

    print("\nPreprocessing traces (canonicalize + features + TGN inputs)...")
    samples_by_path, failures = build_cache(benign + malware, args.workers)
    for path, err in failures:
        print(f"  WARNING skipped {path}: {err}")
    benign = [p for p in benign if p in samples_by_path]
    malware = [p for p in malware if p in samples_by_path]
    print(f"\nValidated dataset:\n  Valid benign    : {len(benign)}\n  Valid malware   : {len(malware)}")

    train_set, val_set, test_set = split_data(benign, malware, seed=args.split_seed)
    set_seed(args.seed)
    all_items = train_set + val_set + test_set
    paths = [p for p, _ in all_items]
    labels = [l for _, l in all_items]
    samples = [samples_by_path[p] for p in paths]
    train_idx = list(range(0, len(train_set)))
    val_idx = list(range(len(train_set), len(train_set) + len(val_set)))
    test_idx = list(range(len(train_set) + len(val_set), len(all_items)))

    print("\nSplits:")
    for name, idx in (("Train", train_idx), ("Val", val_idx), ("Test", test_idx)):
        nb = sum(1 for i in idx if labels[i] == 0)
        nm = sum(1 for i in idx if labels[i] == 1)
        print(f"  {name:5}: {len(idx):4d}  (benign={nb}, malware={nm})")

    with open(SPLIT_FILE, "w") as f:
        json.dump({
            "seed": args.split_seed,
            "data_dir": args.data_dir,
            "exclude_inert": args.exclude_inert,
            "train": [(os.path.relpath(paths[i], PROJECT_ROOT), labels[i]) for i in train_idx],
            "val": [(os.path.relpath(paths[i], PROJECT_ROOT), labels[i]) for i in val_idx],
            "test": [(os.path.relpath(paths[i], PROJECT_ROOT), labels[i]) for i in test_idx],
        }, f, indent=1)

    # ---------------- model ----------------
    model = NPMHybridClassifier(num_nodes=args.num_nodes, stat_dim=feature_dim())
    model.fit_normalizer(np.stack([samples[i]["feats"] for i in train_idx]))
    n_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"\nTrainable parameters: {n_params:,}")

    n_clean = sum(1 for i in train_idx if labels[i] == 0)
    n_mal = sum(1 for i in train_idx if labels[i] == 1)
    pos_weight = n_clean / max(1, n_mal)
    print(f"Positive class weight: {pos_weight:.4f}")

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    steps_per_epoch = max(1, (len(train_idx) + args.batch_size - 1) // args.batch_size)
    scheduler = torch.optim.lr_scheduler.OneCycleLR(
        optimizer, max_lr=args.lr, total_steps=args.epochs * steps_per_epoch,
        pct_start=0.1, anneal_strategy="cos", div_factor=10, final_div_factor=100,
    )

    # ---------------- worker pool ----------------
    pool = None
    if args.workers > 1:
        pool = mp.get_context("spawn").Pool(
            args.workers, initializer=_worker_init,
            initargs=(samples, labels, args.num_nodes, feature_dim(), pos_weight, args.gamma),
        )
    else:
        _worker_init(samples, labels, args.num_nodes, feature_dim(), pos_weight, args.gamma)

    best_val_f1, best_epoch, bad_epochs = -1.0, 0, 0
    tag = f"_{args.tag}" if args.tag else ""
    best_ckpt = CHECKPOINT_DIR / f"scbf_npm_hybrid_best{tag}.pt"
    model_output = MODEL_OUTPUT if not tag else CHECKPOINT_DIR / f"scbf_npm_hybrid_v1{tag}.pt"
    results_file = RESULTS_FILE if not tag else CHECKPOINT_DIR / f"npm_evaluation_results{tag}.json"
    params = list(model.parameters())

    print("\n" + "=" * 80)
    print(f"TRAINING: max {args.epochs} epochs, patience={args.patience}, batch={args.batch_size}")
    print("=" * 80)

    try:
        for epoch in range(1, args.epochs + 1):
            t0 = time.time()
            model.train()
            order = train_idx.copy()
            random.shuffle(order)
            total_loss, total_n = 0.0, 0

            for b in range(0, len(order), args.batch_size):
                batch = order[b:b + args.batch_size]
                state = _cpu_state(model)
                if pool is None:
                    results = [_worker_grads((state, batch))]
                else:
                    results = pool.map(_worker_grads, [(state, s) for s in _shards(batch, args.workers)])

                n_ok = sum(r[2] for r in results)
                if n_ok == 0:
                    continue
                optimizer.zero_grad()
                for grads, _, _ in results:
                    if grads is None:
                        continue
                    for p, g in zip(params, grads):
                        if g is None:
                            continue
                        if p.grad is None:
                            p.grad = g / n_ok
                        else:
                            p.grad.add_(g / n_ok)
                torch.nn.utils.clip_grad_norm_(params, 1.0)
                optimizer.step()
                scheduler.step()
                total_loss += sum(r[1] for r in results)
                total_n += n_ok

            # ---------------- validation ----------------
            model.eval()
            val_logits, kept = run_eval(pool, model, val_idx, args.workers)
            val_labels = torch.tensor([float(labels[i]) for i in kept])
            vm = compute_metrics(val_logits, val_labels, 0.5)

            print(f"\nEpoch {epoch}/{args.epochs}  lr={optimizer.param_groups[0]['lr']:.2e}  "
                  f"({time.time() - t0:.0f}s)")
            print(f"  Train: loss={total_loss / max(1, total_n):.4f}  samples={total_n}")
            print(f"  Val  : {fmt(vm)}")

            if vm["f1"] > best_val_f1:
                best_val_f1, best_epoch, bad_epochs = vm["f1"], epoch, 0
                torch.save({
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "val_metrics": vm,
                    "seed": args.seed,
                    "dataset": "RQ1_NPM",
                    "feature_dim": feature_dim(),
                    "rich": USE_RICH,
                    "max_tgn_events": MAX_TGN_EVENTS,
                }, best_ckpt)
                print(f"  * New best checkpoint (val F1={best_val_f1:.2%})")
            else:
                bad_epochs += 1
                print(f"  No improvement ({bad_epochs}/{args.patience}), best F1={best_val_f1:.2%} @ epoch {best_epoch}")
                if bad_epochs >= args.patience:
                    print("\nEarly stopping.")
                    break

        # ---------------- best model + threshold ----------------
        print("\n" + "=" * 80)
        print(f"LOADING BEST MODEL (epoch {best_epoch})")
        print("=" * 80)
        ckpt = torch.load(best_ckpt, map_location="cpu", weights_only=False)
        model.load_state_dict(ckpt["model_state_dict"])
        model.eval()

        val_logits, kept = run_eval(pool, model, val_idx, args.workers)
        val_labels = torch.tensor([float(labels[i]) for i in kept])
        best_thr, best_thr_f1 = 0.5, -1.0
        for thr in np.arange(0.05, 0.96, 0.01):
            m = compute_metrics(val_logits, val_labels, float(thr))
            if m["f1"] > best_thr_f1 + 1e-9:
                best_thr, best_thr_f1 = float(thr), m["f1"]
        model.threshold.fill_(best_thr)
        val_metrics = compute_metrics(val_logits, val_labels, best_thr)
        print(f"\nValidation threshold: {best_thr:.2f}")
        print(f"Validation : {fmt(val_metrics)}")

        # ---------------- test ----------------
        print("\n" + "=" * 80)
        print("FINAL TEST EVALUATION")
        print("=" * 80)
        test_logits, kept = run_eval(pool, model, test_idx, args.workers)
        test_labels = torch.tensor([float(labels[i]) for i in kept])
        tm = compute_metrics(test_logits, test_labels, best_thr)
        tm_05 = compute_metrics(test_logits, test_labels, 0.5)

        print("\nFINAL NPM TEST RESULTS")
        print("-" * 50)
        print(f"Threshold : {best_thr:.2f}")
        print(f"Accuracy  : {tm['accuracy']:.2%}")
        print(f"Precision : {tm['precision']:.2%}")
        print(f"Recall    : {tm['recall']:.2%}")
        print(f"F1 Score  : {tm['f1']:.2%}")
        print(f"FPR       : {tm['fpr']:.2%}")
        print(f"ROC-AUC   : {tm['auc']:.4f}")
        print(f"(at 0.50) : {fmt(tm_05)}")
        print("\nConfusion Matrix")
        print("                 Predicted")
        print("              Clean  Malicious")
        print(f"Actual Clean  {tm['tn']:5d}  {tm['fp']:5d}")
        print(f"Actual Mal    {tm['fn']:5d}  {tm['tp']:5d}")
        print(f"\nTest samples: {len(test_labels)}   (skipped: {len(test_idx) - len(kept)})")

        # ---------------- save ----------------
        torch.save(model.state_dict(), model_output)
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dataset": "RQ1_NPM",
            "data_dir": args.data_dir,
            "model": os.path.relpath(model_output, PROJECT_ROOT),
            "feature_dim": feature_dim(),
            "rich": USE_RICH,
            "max_tgn_events": MAX_TGN_EVENTS,
            "exclude_inert": args.exclude_inert,
            "best_epoch": best_epoch,
            "threshold": best_thr,
            "validation": val_metrics,
            "test": tm,
            "test_at_0.5": tm_05,
            "splits": {"train": len(train_idx), "val": len(val_idx), "test": len(test_idx)},
            "hyperparameters": vars(args),
        }
        with open(RESULTS_FILE, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nModel saved   -> {MODEL_OUTPUT}")
        print(f"Results saved -> {RESULTS_FILE}")
    finally:
        if pool is not None:
            pool.close()
            pool.join()


if __name__ == "__main__":
    main()
