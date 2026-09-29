"""
Tune the install-time BLOCK threshold at the decision point.

The guard currently inherits mean+2.5sd from the post-install envelope. That
threshold was calibrated for a completed install and was never chosen for a
decision taken at event 1500, so it is arbitrary here — and it showed: a
malicious install scored 6.097 against a 6.186 threshold and was let through.

This scores every held-out trace at the decision point, then sweeps the
threshold to expose the real trade-off: how much malware is stopped at 28% of
the install, against how many legitimate installs are killed.

Both the envelope distance and the classifier probability are swept, and the
better of the two is reported, because there is no reason to assume the
distance is the stronger signal at this point in the install.

Usage:
    python3 -m scbf.detection.tune_block --models models_early --at 1500
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from scbf.envelope.streaming import partial_signature
from scbf.training.train import HybridClassifier, load_events, set_prefix


def collect(model, items, centroid, at):
    """(distance, probability, label) for every trace, scored at `at` events."""
    rows = []
    with torch.no_grad():
        for it in items:
            ev = load_events(it["path"])
            if len(ev) < at * 0.6:          # too short to reach the decision point
                continue
            sig = partial_signature(model, ev, at)
            if sig is None:
                continue
            d = float(np.linalg.norm(sig - centroid))
            p = float(torch.sigmoid(model.head(torch.tensor(sig).unsqueeze(0))).squeeze())
            rows.append((d, p, it["label"], len(ev)))
    return rows


def sweep(rows, idx, name):
    """Print the trade-off curve for one signal, return the best operating points."""
    vals = sorted({r[idx] for r in rows})
    mal = [r for r in rows if r[2] == 1]
    ben = [r for r in rows if r[2] == 0]
    out = []
    for t in vals:
        tp = sum(1 for r in mal if r[idx] >= t)
        fp = sum(1 for r in ben if r[idx] >= t)
        rec = tp / max(1, len(mal))
        fpr = fp / max(1, len(ben))
        prec = tp / max(1, tp + fp)
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        out.append((t, rec, fpr, prec, f1))

    print(f"\n  === {name} ===")
    print(f"  {'threshold':>10}{'blocked':>10}{'false kills':>13}{'precision':>11}{'F1':>8}")
    for target in (0.01, 0.02, 0.05, 0.10):
        ok = [o for o in out if o[2] <= target]
        if not ok:
            print(f"  (no threshold achieves <= {target:.0%} false kills)")
            continue
        best = max(ok, key=lambda o: o[1])
        print(f"  {best[0]:>10.3f}{best[1]:>9.1%}{best[2]:>12.1%}"
              f"{best[3]:>11.1%}{best[4]:>8.1%}   <= {target:.0%} FP budget")
    bestf1 = max(out, key=lambda o: o[4])
    print(f"  {bestf1[0]:>10.3f}{bestf1[1]:>9.1%}{bestf1[2]:>12.1%}"
          f"{bestf1[3]:>11.1%}{bestf1[4]:>8.1%}   <- best F1")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", type=Path, default=Path("models_early"))
    ap.add_argument("--at", type=int, default=1500, help="decision point, in events")
    args = ap.parse_args()

    set_prefix(args.at)
    model = HybridClassifier()
    model.load_state_dict(torch.load(args.models / "scbf_hybrid.pt", map_location="cpu"))
    model.eval()

    env = json.loads((args.models / "envelope.json").read_text())["fused"]
    centroid = np.array(env["centroid"])
    split = json.loads((args.models / "split_info.json").read_text())

    print(f"Decision point: event {args.at}")
    print(f"Current (inherited) BLOCK threshold: {env['block_threshold']:.3f}\n")
    print("Scoring held-out traces at the decision point...")
    rows = collect(model, split["test"], centroid, args.at)
    mal = sum(1 for r in rows if r[2] == 1)
    ben = len(rows) - mal
    frac = np.median([args.at / r[3] for r in rows])
    print(f"  {len(rows)} traces reach event {args.at}  ({mal} malicious, {ben} benign)")
    print(f"  that point is a median {frac:.0%} of the way through an install")

    cur = env["block_threshold"]
    tp = sum(1 for r in rows if r[2] == 1 and r[0] >= cur)
    fp = sum(1 for r in rows if r[2] == 0 and r[0] >= cur)
    print(f"\n  AT THE CURRENT THRESHOLD ({cur:.3f}):")
    print(f"    malware blocked      : {tp}/{mal} ({tp/max(1,mal):.1%})")
    print(f"    benign killed        : {fp}/{ben} ({fp/max(1,ben):.1%})")

    sweep(rows, 0, "envelope distance")
    sweep(rows, 1, "classifier probability")

    print("\n" + "=" * 70)
    print("READ THIS AS: at a false-kill budget you can live with, how much")
    print("malware is stopped at ~{:.0%} of the install rather than after it.".format(frac))


if __name__ == "__main__":
    main()
