"""
Validate per-stage envelopes: can we block mid-install without false positives?

Replays HELD-OUT traces and scores each one at every checkpoint against the
benign envelope calibrated for that same checkpoint. Reports where each trace
would first be blocked, and — the number that decides viability — how many
benign installs would be wrongly terminated.

Usage:
    python3 -m scbf.detection.trajectory_staged --models models --n 15
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from scbf.envelope.streaming import partial_signature
from scbf.training.train import HybridClassifier, load_events


def first_block(model, events, stages):
    """(checkpoint, fraction, distance) where this trace would first be blocked."""
    with torch.no_grad():
        for c_str, st in sorted(stages.items(), key=lambda kv: int(kv[0])):
            c = int(c_str)
            if len(events) < c * 0.5:
                continue
            sig = partial_signature(model, events, c)
            if sig is None:
                continue
            d = float(np.linalg.norm(sig - np.array(st["centroid"])))
            if d >= st["block_threshold"]:
                return c, min(1.0, c / len(events)), d
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", type=Path, default=Path("models"))
    ap.add_argument("--n", type=int, default=15)
    args = ap.parse_args()

    model = HybridClassifier()
    model.load_state_dict(torch.load(args.models / "scbf_hybrid.pt", map_location="cpu"))
    model.eval()

    stages = json.loads((args.models / "envelope_streaming.json").read_text())["stages"]
    split = json.loads((args.models / "split_info.json").read_text())

    summary = {}
    for label, want in (("MALICIOUS", 1), ("BENIGN", 0)):
        items = [i for i in split["test"] if i["label"] == want][: args.n]
        print(f"=== {label} ===")
        print(f"  {'package':<32}{'events':>8}{'blocked at':>22}")
        hits = []
        for it in items:
            ev = load_events(it["path"])
            if not ev:
                continue
            fb = first_block(model, ev, stages)
            name = Path(it["path"]).stem[:30]
            if fb:
                c, frac, d = fb
                print(f"  {name:<32}{len(ev):>8}   ev {c} ({frac:.0%}) d={d:.2f}")
                hits.append(frac)
            else:
                print(f"  {name:<32}{len(ev):>8}{'never':>22}")
        summary[label] = (hits, len(items))
        print()

    mh, mn = summary["MALICIOUS"]
    bh, bn = summary["BENIGN"]
    print("=" * 68)
    print("MID-INSTALL BLOCKING — VIABILITY")
    print("=" * 68)
    print(f"  malicious blocked : {len(mh)}/{mn}  ({len(mh)/max(1,mn):.0%} — streaming recall)")
    print(f"  benign  blocked   : {len(bh)}/{bn}  ({len(bh)/max(1,bn):.0%} — FALSE POSITIVES)")
    if mh:
        print(f"\n  earliest malicious block : {min(mh):.0%} of the install")
        print(f"  median  malicious block  : {np.median(mh):.0%}")
        early = sum(1 for f in mh if f <= 0.5)
        print(f"  stopped before halfway   : {early}/{len(mh)}")
    print()
    fp = len(bh) / max(1, bn)
    if fp > 0.10:
        print(f"  NOT VIABLE at these thresholds: {fp:.0%} of benign installs would be")
        print("  terminated. Raise the per-stage thresholds or require agreement")
        print("  across consecutive checkpoints before acting.")
    elif not mh:
        print("  NOT VIABLE: no malicious trace crosses its stage threshold.")
    else:
        print(f"  VIABLE: {len(mh)/max(1,mn):.0%} of malware stopped mid-install at a")
        print(f"  {fp:.0%} false-positive rate. The payload is interrupted rather than")
        print("  merely reported after the fact.")


if __name__ == "__main__":
    main()
