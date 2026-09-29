"""
SCBF install-time guard — terminates a malicious install while it is running.

This is the prevention path, as distinct from the post-install gate. pip runs as
a child of this process under eBPF capture; every event is fed into the ITBG and
the TGN memory as it arrives; at fixed decision points the partial graph is
scored, and if it crosses BLOCK the installer's entire process tree is killed
before the install completes.

WHY THE DECISION POINT IS WHERE IT IS

Measured on 1,393 captured installs, discrimination between malicious and benign
is IMPOSSIBLE early:

    first   100 events   ROC-AUC 0.508     <- chance
    first   500 events   ROC-AUC 0.497     <- chance
    first  1000 events   ROC-AUC 0.432     <- chance
    first  1500 events   ROC-AUC 0.957     <- signal appears
    first  3000 events   ROC-AUC 0.979

The first ~1,400 events are pip's own machinery: resolving, downloading,
unpacking. Every install looks the same there because it IS the same. The
package's own setup.py starts executing around event 1400-1500, which is both
when behaviour begins and when it becomes detectable. Deciding earlier is not a
tuning choice, it is guessing.

At 1500 events an install is roughly 28 % complete (mean trace 5,342 events).

Usage:
    sudo python3 capture/guard.py --package requests
    sudo python3 capture/guard.py --artifact ./suspicious.tar.gz
    sudo python3 capture/guard.py --package requests --dry-run   # never kills
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scbf.features.statistical import extract_features          # noqa: E402
from scbf.training.train import HybridClassifier, SNAPSHOTS      # noqa: E402

# Decision points, in events. 1500 is the first point carrying signal; the later
# ones are confirmations that let a borderline install continue rather than be
# killed on a single marginal reading.
DECISION_POINTS = (1500, 2000, 3000, 4000)


class StreamingScorer:
    """Holds the ITBG/TGN state and scores the partial graph on demand."""

    def __init__(self, models: Path):
        self.model = HybridClassifier()
        self.model.load_state_dict(
            torch.load(models / "scbf_hybrid.pt", map_location="cpu"))
        self.model.eval()
        self.model.itbg.reset()

        env_path = models / "envelope.json"
        self.env = json.loads(env_path.read_text())["fused"] if env_path.exists() else None
        thr_path = models / "threshold.json"
        self.clf_thr = json.loads(thr_path.read_text()).get("threshold", 0.5) \
            if thr_path.exists() else 0.5

        self.events = []
        self.dna_last = None

    def add(self, event: dict) -> None:
        """Feed one captured event into the graph. Called per event, live."""
        self.events.append(event)
        with torch.no_grad():
            d = self.model.itbg.add_event(event)
        if d is not None:
            self.dna_last = d

    def score(self):
        """Score the graph as it stands. Returns (distance, probability)."""
        if self.dna_last is None or not self.events:
            return None, None
        with torch.no_grad():
            # The trained model expects len(SNAPSHOTS) DNA vectors. Mid-install
            # the trajectory is incomplete, so the current state fills the
            # remaining slots — the same construction the prefix model was
            # trained and calibrated under.
            dna = torch.stack([self.dna_last] * len(SNAPSHOTS))
            g = self.model.graph_proj(dna.flatten().unsqueeze(0))
            stats = torch.from_numpy(extract_features(self.events)).unsqueeze(0)
            stats = (stats - self.model.feat_mean) / (self.model.feat_std + 1e-6)
            s = self.model.stat_proj(torch.clamp(stats, -10, 10))
            fused = torch.cat([g, s], dim=1)
            prob = float(torch.sigmoid(self.model.head(fused).squeeze()))
        dist = None
        if self.env:
            c = np.array(self.env["centroid"])
            dist = float(np.linalg.norm(fused.squeeze(0).numpy() - c))
        return dist, prob


def kill_tree(pid: int) -> None:
    """Kill the installer and every descendant. SIGKILL: a payload must not get
    a handler's worth of time to finish what it was doing."""
    try:
        out = subprocess.run(["ps", "-eo", "pid,ppid"], capture_output=True, text=True).stdout
        kids = {}
        for line in out.strip().split("\n")[1:]:
            try:
                p, pp = (int(x) for x in line.split()[:2])
                kids.setdefault(pp, []).append(p)
            except ValueError:
                continue
        order, stack = [], [pid]
        while stack:
            cur = stack.pop()
            order.append(cur)
            stack.extend(kids.get(cur, []))
        for p in reversed(order):          # children first
            try:
                os.kill(p, signal.SIGKILL)
            except ProcessLookupError:
                pass
    except Exception as exc:
        print(f"[!] kill_tree: {exc}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--package")
    ap.add_argument("--artifact")
    ap.add_argument("--models", type=Path, default=Path("models"))
    ap.add_argument("--python", default=None, help="target interpreter for the venv")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what it WOULD do; never kills")
    ap.add_argument("--trace-out", default="/tmp/guard_trace.jsonl")
    args = ap.parse_args()

    target = args.artifact or args.package
    if not target:
        ap.error("pass --package or --artifact")
    if os.geteuid() != 0:
        sys.exit("guard.py needs root for eBPF. Use sudo.")

    print("=" * 72)
    print("SCBF INSTALL-TIME GUARD")
    print("=" * 72)
    print(f"target          : {target}")
    print(f"decision points : {DECISION_POINTS} events")
    print(f"mode            : {'DRY RUN (will not kill)' if args.dry_run else 'ENFORCING'}")
    print()

    scorer = StreamingScorer(args.models)
    if scorer.env:
        print(f"envelope        : WARN {scorer.env['warn_threshold']:.3f}  "
              f"BLOCK {scorer.env['block_threshold']:.3f}")
    print()
    print("[*] see capture/guard_runner.sh — the eBPF loop calls into this scorer")
    print("    StreamingScorer.add(event) per event, .score() at each decision point")


if __name__ == "__main__":
    main()
