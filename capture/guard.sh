#!/bin/bash

set -u

PACKAGE="${1:-}"
PYTHON_BIN="${2:-}"
ARTIFACT="${3:-}"
OUTPUT="${4:-}"

if [ -z "$PACKAGE" ] || [ -z "$PYTHON_BIN" ] || [ -z "$ARTIFACT" ] || [ -z "$OUTPUT" ]; then
    echo "Usage:"
    echo "  sudo ./monitor.sh PACKAGE PYTHON_BIN ARTIFACT OUTPUT"
    exit 2
fi

echo "============================================================"
echo "[+] SCBF INSTALL-TIME GUARD (enforcing)"
echo "[+] Package : $PACKAGE"
echo "[+] Python  : $PYTHON_BIN"
echo "[+] Artifact: $ARTIFACT"
echo "[+] Output  : $OUTPUT"
echo "============================================================"

exec "${SCBF_PYTHON:-/home/ubuntu/scbf2/.venv/bin/python}" - "$PACKAGE" "$PYTHON_BIN" "$ARTIFACT" "$OUTPUT" <<'PYTHON'
import sys
import os
import json
import time
import subprocess

# bcc is installed for the SYSTEM interpreter; torch/numpy live in the venv.
# Both are Python 3.14, so exposing dist-packages lets one process have both.
sys.path.append("/usr/lib/python3/dist-packages")
from bcc import BPF

# ---------------------------------------------------------------- SCBF guard
sys.path.insert(0, "/home/ubuntu/scbf2")
import numpy as _np
import torch as _torch
from scbf.features.statistical import extract_features as _feat
from scbf.training.train import HybridClassifier as _HC, SNAPSHOTS as _SNAP

# Decision points in events. Nothing earlier is actionable: measured over 1,393
# installs, ROC-AUC is 0.508 at 100 events, 0.497 at 500, 0.432 at 1000, and
# only reaches 0.957 by 1500. The first ~1,400 events are pip's own resolve /
# download / unpack machinery and are identical for every package; the target's
# setup.py starts executing around there, which is when behaviour begins and
# when it becomes detectable.
_MODELS = os.environ.get("SCBF_MODELS", "/home/ubuntu/scbf2/models_pypi")

# The first decision point is the window the model was TRAINED on. Scoring a
# prefix model at an earlier event would feed it a window it has never seen,
# which is the mistake that made the first streaming attempt look unusable.
# Later points re-check with more evidence.
try:
    with open(os.path.join(_MODELS, "threshold.json")) as _f:
        _P0 = int(json.load(_f).get("event_prefix") or 3000)
except Exception:
    _P0 = 3000
_MW = os.path.join(_MODELS, "multiwindow_gbm.joblib")
if os.path.exists(_MW):
    try:
        import joblib as _jl
        _DECISIONS = tuple(sorted(_jl.load(_MW)["windows"]))
    except Exception:
        _DECISIONS = tuple(sorted({_P0, _P0 + 1000, _P0 + 2000}))
else:
    # Fixed-prefix fallback. It only reaches a verdict on the ~59% of installs
    # that run past _P0; the rest finish first and are judged after the payload
    # has already executed, which is detection, not blocking.
    _DECISIONS = tuple(sorted({_P0, _P0 + 1000, _P0 + 2000}))
_DRY = os.environ.get("SCBF_DRY_RUN", "0") == "1"


class _Guard:
    """3-seed TGN ensemble, optionally followed by a gradient-boosting stage.

    All three members share ONE train/val/test split. They did not always:
    --seed used to drive both model init and the split, so each member had a
    different partition and scoring the ensemble on one member's test set
    meant the others had trained on 145/210 of it. That inflated PyPI test F1
    to 93.22%; the clean figure for the TGN alone is 89.91%.

    On PyPI a gradient-boosting stage over [TGN score + the 51 statistical
    features] lifts test F1 to 92.86% (precision 98.11%, recall 88.14%),
    above OSCAR's 91.00/99.00/85.00. It is loaded from hybrid_gbm.joblib when
    present. On npm it is not: there the hybrid reproduces the TGN's
    predictions exactly, so the extra stage buys nothing and is skipped."""

    def __init__(self):
        dirs = os.environ.get(
            "SCBF_ENSEMBLE",
            "/home/ubuntu/scbf2/models_pypi/seed42,"
            "/home/ubuntu/scbf2/models_pypi/seed7,"
            "/home/ubuntu/scbf2/models_pypi/seed1337").split(",")
        self.models = []
        for d in dirs:
            d = d.strip()
            if not os.path.exists(os.path.join(d, "scbf_hybrid.pt")):
                continue
            mm = _HC()
            mm.load_state_dict(_torch.load(os.path.join(d, "scbf_hybrid.pt"),
                                           map_location="cpu"))
            mm.eval()
            self.models.append(mm)
        if not self.models:
            raise SystemExit("guard: no ensemble members found")
        print(f"[guard] ensemble of {len(self.models)} models", flush=True)
        self.model = self.models[0]          # its ITBG drives graph replay
        self.model.itbg.reset()
        # The envelope is a corroborating distance signal, not the decision.
        # npm ships without one, so its absence must not be fatal.
        try:
            with open(os.path.join(_MODELS, "envelope.json")) as f:
                self.env = json.load(f)["fused"]
        except Exception:
            self.env = {"centroid": None, "block_threshold": float("inf"),
                        "warn_threshold": float("inf")}
        # Optional hybrid stage. Absent (npm) -> plain TGN ensemble.
        self.gbms, self.gbm_thr = None, None
        self.mw_thr = None            # {window: threshold}
        _mwp = os.path.join(_MODELS, "multiwindow_gbm.joblib")
        if os.path.exists(_mwp):
            try:
                import joblib as _joblib
                _b = _joblib.load(_mwp)
                self.gbms = _b["gbms"]
                self.mw_thr = {int(k): float(v) for k, v in _b["thresholds"].items()}
                print(f"[guard] multi-window stage loaded: windows "
                      f"{sorted(self.mw_thr)} thresholds "
                      f"{ {k: round(v,4) for k,v in sorted(self.mw_thr.items())} }",
                      flush=True)
            except Exception as _e:
                print(f"[guard] multi-window stage unavailable ({_e})", flush=True)
        _hp = os.environ.get("SCBF_HYBRID",
                             os.path.join(_MODELS, "hybrid_gbm.joblib"))
        if self.gbms is None and os.path.exists(_hp):
            try:
                import joblib as _joblib
                _b = _joblib.load(_hp)
                self.gbms, self.gbm_thr = _b["gbms"], float(_b["threshold"])
                print(f"[guard] hybrid GBM stage loaded "
                      f"({len(self.gbms)} members, threshold {self.gbm_thr:.4f})",
                      flush=True)
            except Exception as _e:
                print(f"[guard] hybrid stage unavailable ({_e}); "
                      f"falling back to the TGN ensemble", flush=True)
        # The block threshold must match the stage that produces the score.
        # It was hard-coded to 0.1925, which belongs to the old TGN-only model
        # AND was tuned on a leaked split. GBM probabilities are on a different
        # scale entirely, so a stale constant here silently mis-fires.
        if self.gbm_thr is not None:
            self.p_threshold = self.gbm_thr
        else:
            try:
                with open(os.path.join(_MODELS, "threshold.json")) as f:
                    self.p_threshold = float(json.load(f)["threshold"])
            except Exception:
                self.p_threshold = 0.5
        _ov = os.environ.get("SCBF_BLOCK_P")
        if _ov:
            self.p_threshold = float(_ov)
        print(f"[guard] decision threshold {self.p_threshold:.4f}", flush=True)
        self.events = []; self.dna = None; self.fired = set(); self.verdict = None

    def add(self, ev):
        # Events are only accumulated here. The graph is replayed at each
        # decision point instead of kept incrementally, because the model was
        # TRAINED on snapshots at 12.5%..100% of the event window. Scoring with
        # a different construction than training would compare the install
        # against something the model never learned.
        self.events.append(ev)

    def should_check(self):
        n = len(self.events)
        for p in _DECISIONS:
            if n >= p and p not in self.fired:
                self.fired.add(p)
                return p
        return None

    def score(self):
        n = len(self.events)
        if n == 0:
            return None, None
        # Each ensemble member runs its OWN full forward pass. Sharing one
        # member's fused vector across the others' heads is invalid: every
        # model has its own graph_proj, stat_proj, feature normalisation and
        # TGN weights, so a head receives input it was never trained on. That
        # bug compressed every score into 0.33-0.39 and blocked 10/10 clean
        # packages.
        probs, dist = [], None
        for mi, mm in enumerate(self.models):
            mm.itbg.reset()
            marks = {max(0, int(n * f) - 1) for f in _SNAP}
            dnas, last = [], None
            with _torch.no_grad():
                for i, e in enumerate(self.events):
                    d = mm.itbg.add_event(e)
                    if d is not None:
                        last = d
                    if i in marks:
                        dnas.append(last)
                dnas = [d for d in dnas if d is not None]
                if not dnas:
                    continue
                while len(dnas) < len(_SNAP):
                    dnas.append(dnas[-1])
                dna = _torch.stack(dnas[:len(_SNAP)])
                g = mm.graph_proj(dna.flatten().unsqueeze(0))
                st = _torch.from_numpy(_feat(self.events)).unsqueeze(0)
                st = (st - mm.feat_mean) / (mm.feat_std + 1e-6)
                sp_ = mm.stat_proj(_torch.clamp(st, -10, 10))
                fu = _torch.cat([g, sp_], dim=1)
                probs.append(float(_torch.sigmoid(mm.head(fu).squeeze())))
                if mi == 0 and self.env.get("centroid") is not None:
                    dist = float(_np.linalg.norm(
                        fu.squeeze(0).numpy() - _np.array(self.env["centroid"])))
        if not probs:
            return None, None
        if dist is None:
            dist = 0.0          # no envelope (npm): distance is unused
        tgn = float(_np.mean(probs))
        if self.gbms:
            # Same input the stage was fitted on: the TGN ensemble score, the
            # RAW (un-normalised) statistical features, and -- for the
            # multi-window stage -- how much of the install has been seen, so
            # it can calibrate instead of assuming a fixed trace length.
            v = [[tgn], _feat(self.events)]
            if self.mw_thr is not None:
                v.append([float(self._window_for(n))])
            x = _np.concatenate(v).reshape(1, -1)
            tgn = float(_np.mean([g.predict_proba(x)[0, 1] for g in self.gbms]))
        return dist, tgn

    def _window_for(self, n):
        """The calibrated window this many events belongs to."""
        ws = sorted(self.mw_thr) if self.mw_thr else [3000]
        for w in ws:
            if n <= w:
                return w
        return ws[-1]

    def threshold_for(self, n):
        if self.mw_thr:
            return self.mw_thr[self._window_for(n)]
        return self.p_threshold

    def _unused(self):
        with _torch.no_grad():
            # Replay exactly as training did: the window seen so far IS the
            # trace, snapshots taken at fixed fractions of it.
            self.model.itbg.reset()
            marks = {max(0, int(n * f) - 1) for f in _SNAP}
            dnas, last = [], None
            for i, e in enumerate(self.events):
                d = self.model.itbg.add_event(e)
                if d is not None:
                    last = d
                if i in marks:
                    dnas.append(last)
            dnas = [d for d in dnas if d is not None]
            if not dnas:
                return None, None
            while len(dnas) < len(_SNAP):
                dnas.append(dnas[-1])
            dna = _torch.stack(dnas[:len(_SNAP)])
            g = self.model.graph_proj(dna.flatten().unsqueeze(0))
            st = _torch.from_numpy(_feat(self.events)).unsqueeze(0)
            st = (st - self.model.feat_mean) / (self.model.feat_std + 1e-6)
            s = self.model.stat_proj(_torch.clamp(st, -10, 10))
            fused = _torch.cat([g, s], dim=1)
            probs = [float(_torch.sigmoid(mm.head(fused).squeeze()))
                     for mm in self.models]
            prob = float(_np.mean(probs))
        dist = float(_np.linalg.norm(fused.squeeze(0).numpy()
                                     - _np.array(self.env["centroid"])))
        return dist, prob


def _kill_tree(pid):
    import signal as _sig
    try:
        out = subprocess.run(["ps", "-eo", "pid,ppid"], capture_output=True,
                             text=True).stdout
        kids = {}
        for line in out.strip().split("\n")[1:]:
            try:
                p, pp = (int(x) for x in line.split()[:2])
                kids.setdefault(pp, []).append(p)
            except ValueError:
                pass
        order, stack = [], [pid]
        while stack:
            c = stack.pop(); order.append(c); stack.extend(kids.get(c, []))
        for p in reversed(order):
            try:
                os.kill(p, _sig.SIGKILL)
            except ProcessLookupError:
                pass
    except Exception as e:
        print("[!] kill_tree:", e)


_guard = _Guard()
_ROOT_PID = [0]
# -------------------------------------------------------------- end guard


PACKAGE = sys.argv[1]
PYTHON_BIN = sys.argv[2]
ARTIFACT = sys.argv[3]
OUTPUT = sys.argv[4]


if os.geteuid() != 0:
    print("[ERROR] Monitor must run as root.")
    sys.exit(1)

os.makedirs(os.path.dirname(OUTPUT) or ".", exist_ok=True)

try:
    os.remove(OUTPUT)
except FileNotFoundError:
    pass


# ============================================================
# eBPF PROGRAM
# ============================================================

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>

struct event_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char fname[512];
    u64 ts;
    u32 type;
    u32 flags;   /* openat flags, or connect dest port */
    u32 addr;    /* connect dest IPv4, network byte order */
};

BPF_PERF_OUTPUT(events);

BPF_HASH(tracked, u32, u8, 32768);

BPF_PERCPU_ARRAY(event_scratch, struct event_t, 1);


static int is_tracked(u32 pid)
{
    u8 *value = tracked.lookup(&pid);

    if (value)
        return 1;

    return 0;
}


/*
 * Track descendants in-kernel.
 *
 * The userspace sync_process_tree() walks /proc periodically, so a
 * short-lived child (curl, sh, base64) can fork, exec and exit between
 * two polls and never get tracked at all. That race is why execve was
 * captured in only 1 of 1344 traces in the zenodo_13746167 collection.
 * Inheriting the tracked flag at fork time closes it.
 */
TRACEPOINT_PROBE(sched, sched_process_fork)
{
    u32 parent = (u32)args->parent_pid;
    u32 child  = (u32)args->child_pid;

    u8 *value = tracked.lookup(&parent);

    if (!value)
        return 0;

    u8 one = 1;
    tracked.update(&child, &one);

    return 0;
}


/*
 * 0 = exec
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_tracked(pid))
        return 0;

    u32 zero = 0;

    struct event_t *event =
        event_scratch.lookup(&zero);

    if (!event)
        return 0;

    event->pid = pid;
    event->ppid = 0;
    event->ts = bpf_ktime_get_ns();
    event->type = 0;

    bpf_get_current_comm(
        &event->comm,
        sizeof(event->comm)
    );

    bpf_probe_read_user_str(
        &event->fname,
        sizeof(event->fname),
        args->filename
    );

    events.perf_submit(
        args,
        event,
        sizeof(*event)
    );

    return 0;
}


/*
 * 1 = open
 */
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_tracked(pid))
        return 0;

    u32 zero = 0;

    struct event_t *event =
        event_scratch.lookup(&zero);

    if (!event)
        return 0;

    event->pid = pid;
    event->ppid = 0;
    event->ts = bpf_ktime_get_ns();
    event->type = 1;
    event->flags = (u32)args->flags;
    event->addr = 0;

    bpf_get_current_comm(
        &event->comm,
        sizeof(event->comm)
    );

    bpf_probe_read_user_str(
        &event->fname,
        sizeof(event->fname),
        args->filename
    );

    events.perf_submit(
        args,
        event,
        sizeof(*event)
    );

    return 0;
}


/*
 * 2 = connect
 */
TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_tracked(pid))
        return 0;

    u32 zero = 0;

    struct event_t *event =
        event_scratch.lookup(&zero);

    if (!event)
        return 0;

    event->pid = pid;
    event->ppid = 0;
    event->ts = bpf_ktime_get_ns();
    event->type = 2;

    bpf_get_current_comm(
        &event->comm,
        sizeof(event->comm)
    );

    /*
     * Read the actual destination. The previous version wrote the
     * literal string "connect" here, so every network event was
     * indistinguishable from every other one -- C2 traffic looked
     * exactly like pip fetching from PyPI.
     */
    event->flags = 0;
    event->addr = 0;

    struct sockaddr *sa = (struct sockaddr *)args->uservaddr;
    u16 family = 0;

    bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        u16 dport = 0;
        u32 daddr = 0;

        bpf_probe_read_user(&dport, sizeof(dport), &sin->sin_port);
        bpf_probe_read_user(&daddr, sizeof(daddr), &sin->sin_addr);

        event->flags = (u32)bpf_ntohs(dport);
        event->addr = daddr;
    }

    event->fname[0] = 'c';
    event->fname[1] = 'o';
    event->fname[2] = 'n';
    event->fname[3] = 'n';
    event->fname[4] = 'e';
    event->fname[5] = 'c';
    event->fname[6] = 't';
    event->fname[7] = '\0';

    events.perf_submit(
        args,
        event,
        sizeof(*event)
    );

    return 0;
}
"""


# ============================================================
# LOAD BPF
# ============================================================

print("[+] Loading eBPF program...")

try:
    bpf = BPF(text=BPF_PROGRAM)
except Exception as e:
    print("[ERROR] Failed to load eBPF:")
    print(e)
    sys.exit(1)

print("[+] eBPF loaded successfully.")


events = []
lost_events = 0


EVENT_TYPES = {
    0: "exec",
    1: "open",
    2: "connect",
}


def handle_lost(lost):
    global lost_events
    lost_events += lost


def get_ppid(pid):
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            data = f.read()

        close_paren = data.rfind(")")

        if close_paren == -1:
            return 0

        fields = data[close_paren + 2:].split()

        return int(fields[1])

    except Exception:
        return 0


def get_children(pid):
    children = set()

    try:
        for entry in os.listdir("/proc"):

            if not entry.isdigit():
                continue

            child = int(entry)

            if get_ppid(child) == pid:
                children.add(child)

    except Exception:
        pass

    return children


def get_process_tree(pid):
    tree = {pid}
    queue = [pid]

    while queue:

        parent = queue.pop()

        for child in get_children(parent):

            if child not in tree:

                tree.add(child)
                queue.append(child)

    return tree


def sync_process_tree(root_pid):

    tree = get_process_tree(root_pid)

    tracked_map = bpf["tracked"]

    for pid in tree:

        try:

            key = tracked_map.Key(pid)

            tracked_map[key] = tracked_map.Leaf(1)

        except Exception:
            pass

    return tree


def handle_event(cpu, data, size):

    event = bpf["events"].event(data)

    pid = int(event.pid)

    ppid = get_ppid(pid)

    comm = bytes(event.comm).split(
        b"\0",
        1
    )[0].decode(
        "utf-8",
        errors="replace"
    )

    fname = bytes(event.fname).split(
        b"\0",
        1
    )[0].decode(
        "utf-8",
        errors="replace"
    )

    event_type = EVENT_TYPES.get(
        int(event.type),
        "unknown"
    )

    record = {
        "type": event_type,
        "pid": pid,
        "ppid": ppid,
        "comm": comm,
        "fname": fname,
        "ts": int(event.ts),
    }

    flags = int(event.flags)

    if event_type == "connect":
        # Destination is the whole point of a network event.
        addr = int(event.addr)
        if addr:
            record["daddr"] = ".".join(
                str((addr >> (8 * i)) & 0xFF) for i in range(4)
            )
        record["dport"] = flags

    elif event_type == "open":
        # O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200, O_APPEND=0x400
        record["flags"] = flags
        record["write"] = bool(flags & (1 | 2 | 0x40 | 0x200 | 0x400))

    events.append(record)

    # ---- SCBF: stream the event into the graph, decide at checkpoints ----
    _guard.add(record)
    _pt = _guard.should_check()
    if _pt is not None and _guard.verdict is None:
        _d, _p = _guard.score()
        if _d is not None:
            _blk = _guard.env["block_threshold"]
            _wrn = _guard.env["warn_threshold"]
            # Decision is on the classifier probability, at the threshold that
            # was tuned on VALIDATION for whichever stage is loaded. The
            # envelope distance is kept only as a corroborating signal.
            _PTHR = _guard.threshold_for(len(_guard.events))
            if _p >= _PTHR:
                _v = "BLOCK"
            elif _p >= _PTHR * 0.6 or _d >= _wrn:
                _v = "WARN"
            else:
                _v = "ALLOW"
            print(f"[guard] event {_pt}: p(malicious)={_p:.4f} distance={_d:.3f} -> {_v}",
                  flush=True)
            if _v == "BLOCK":
                _guard.verdict = "BLOCK"
                if _DRY:
                    print("[guard] DRY RUN — would terminate the installer now",
                          flush=True)
                else:
                    print(f"[guard] TERMINATING installer process tree "
                          f"(pid {_ROOT_PID[0]}) at event {_pt}", flush=True)
                    _kill_tree(_ROOT_PID[0])


bpf["events"].open_perf_buffer(
    handle_event,
    page_cnt=128,
    lost_cb=handle_lost,
)


# ============================================================
# START PIP
# ============================================================

print(f"[+] Starting {os.environ.get('SCBF_ECOSYSTEM','pypi')} installation...")

# SCBF_ECOSYSTEM selects the package manager. The eBPF probes are identical
# for both -- fork/execve/openat/connect mean the same thing whichever
# installer runs -- so only the traced command changes.
ECOSYSTEM = os.environ.get("SCBF_ECOSYSTEM", "pypi")

if ECOSYSTEM == "npm":
    # For npm the second positional argument carries the install prefix
    # instead of a python binary.
    NPM_PREFIX = PYTHON_BIN
    cmd = [
        "npm", "install", ARTIFACT,
        "--prefix", NPM_PREFIX,
        # npm's content-addressable cache makes consecutive installs
        # dependent: a warm _cacache changes the syscall trace of the next
        # package. Give every install its own.
        "--cache", os.path.join(NPM_PREFIX, ".npm-cache"),
        # Lifecycle scripts are where npm malware lives, so they stay ON.
        "--foreground-scripts",
        "--no-audit", "--no-fund",
    ]
else:
    cmd = [
    PYTHON_BIN,
    "-m",
    "pip",
    "install",
    # Build isolation is left ON (pip default). Disabling it fails any
    # package whose setup.py imports a build dependency (numpy, cython,
    # burger, ...), which real libraries do constantly and malware almost
    # never does -- so it depresses the BENIGN success rate specifically
    # and bakes a class-correlated bias into the dataset. Measured with
    # the flag on: 63.3% benign vs 77.6% malware success.
        "--disable-pip-version-check",
        ARTIFACT,
    ]

try:

    # The monitor itself must run as root (eBPF/BCC requires it),
    # but pip / package installation should NOT run as root, otherwise
    # root-owned files end up inside the target virtualenv.
    #
    # By default we drop to the user in SUDO_USER (the user who invoked
    # `sudo`). This can be overridden with the SCBF_USER env variable.
    drop_user = os.environ.get("SCBF_USER") or os.environ.get("SUDO_USER") or ""

    if drop_user and drop_user != "root":
        install_cmd = ["sudo", "-u", drop_user, "-H", *cmd]
        print(f"[+] Running pip as user: {drop_user}")
    else:
        # No unprivileged user available — run as root.
        # Not ideal (root-owned venv), but functional.
        install_cmd = cmd
        print("[!] Running pip as root (no SUDO_USER / SCBF_USER set).")
        print("[!] Consider running with:  sudo -E ./monitor.sh  ...  so SUDO_USER is preserved.")

    proc = subprocess.Popen(
        install_cmd,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

except Exception as e:

    print("[ERROR] Failed to start pip:")
    print(e)

    sys.exit(1)


root_pid = proc.pid
_ROOT_PID[0] = root_pid

print(f"[+] pip PID: {root_pid}")
print("[+] Monitoring process tree...")
print()


# ============================================================
# MONITOR LOOP
# ============================================================

while proc.poll() is None:

    sync_process_tree(root_pid)

    try:

        bpf.perf_buffer_poll(
            timeout=100
        )

    except KeyboardInterrupt:

        proc.terminate()
        break

    except Exception:
        pass


returncode = proc.wait()


# ============================================================
# FINAL DRAIN
# ============================================================

print()
print("[+] pip finished.")
print(f"[+] pip return code : {returncode}")
print("[+] Draining remaining eBPF events...")

for _ in range(10):

    try:

        bpf.perf_buffer_poll(
            timeout=50
        )

    except Exception:
        pass


# ============================================================
# WRITE JSONL
# ============================================================

print("[+] Writing JSONL...")

with open(
    OUTPUT,
    "w",
    encoding="utf-8",
) as f:

    for event in events:

        f.write(
            json.dumps(event)
            + "\n"
        )


pids = set(
    event["pid"]
    for event in events
)


print()
print("============================================================")
# FINAL CHECK. 36.8% of malicious installs finish in under 3000 events and so
# never reach a decision point. Skipping them entirely is not "no verdict", it
# is a silent allow. The model was trained on min(prefix, len(trace)) windows,
# so a completed short trace is in-distribution and can be scored directly.
# The install has finished by now, so this cannot interrupt it -- but the
# caller discards the environment on BLOCK, so the package never survives.
if _guard.verdict is None and _guard.events:
    _d, _p = _guard.score()
    if _d is not None:
        _PT = _guard.threshold_for(len(_guard.events))
        print(f"[guard] final ({len(_guard.events)} events, install already "
              f"complete): p(malicious)={_p:.4f} distance={_d:.3f}", flush=True)
        if _p >= _PT:
            _guard.verdict = "BLOCK"
            print("[guard] BLOCK on the completed trace — install will be discarded",
                  flush=True)

print("[+] GUARD COMPLETE")
if _guard.verdict == "BLOCK":
    print("[+] VERDICT        : BLOCKED — install terminated mid-flight")
else:
    print("[+] VERDICT        : ALLOWED — no decision point crossed BLOCK")
print(f"[+] events seen    : {len(_guard.events)}")
print("============================================================")
print(f"[+] Package         : {PACKAGE}")
print(f"[+] pip return code : {returncode}")
print(f"[+] Events captured : {len(events)}")
print(f"[+] Events lost     : {lost_events}")
print(f"[+] PIDs with events: {len(pids)}")
print(f"[+] Output          : {OUTPUT}")

# pip's return code alone is misleading here: when the guard kills the process
# tree, pip can still have exited 0 on a run that was terminated, so printing
# "INSTALLATION SUCCESS" next to a BLOCK verdict reads as a contradiction.
if _guard.verdict == "BLOCK":
    print("[!] INSTALLATION BLOCKED — terminated by the guard; "
          "any files already written are discarded by the caller")
elif returncode == 0:
    print("[+] INSTALLATION SUCCESS")
else:
    print("[!] INSTALLATION FAILED")

print("============================================================")


# Return the ACTUAL pip return code.
sys.exit(returncode)
PYTHON
