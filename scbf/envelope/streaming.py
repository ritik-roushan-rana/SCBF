"""
Per-stage envelopes for mid-install blocking.

The post-install envelope compares a COMPLETED install against completed benign
installs. That comparison is invalid mid-run: a half-finished install has a
different signature from a finished one purely because it is half finished, not
because it is malicious. Measured directly, scoring partial installs against the
completed-install envelope blocks 6 of 8 benign traces.

The fix is to compare like with like. A benign centroid and threshold are
calibrated at each of a series of event-count checkpoints, so an install that
has emitted 500 events is judged against benign installs at their 500th event.

The signature at a checkpoint is the fused 192-dim representation computed from
the events seen so far: the DNA trajectory to date, padded across the 8 snapshot
slots, concatenated with the statistical descriptors of the partial event
stream. This is exactly what a streaming monitor can compute at run time.

Usage:
    python3 -m scbf.envelope.streaming --traces data/traces --models models
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from scbf.features.statistical import extract_features
from scbf.training.train import HybridClassifier, load_events, SNAPSHOTS

# Checkpoints in events. Dense early, because the point of streaming is to stop
# a payload before it finishes.
CHECKPOINTS = (250, 500, 1000, 1500, 2000, 3000, 4000, 6000)


def partial_signature(model, events, upto):
    """The fused 192-dim signature computable from the first `upto` events."""
    model.itbg.reset()
    dnas = []
    n = min(upto, len(events))
    marks = {max(0, int(n * f) - 1) for f in SNAPSHOTS}
    last = None
    for i, e in enumerate(events[:n]):
        d = model.itbg.add_event(e)
        if d is not None:
            last = d
        if i in marks:
            dnas.append(last)
    dnas = [d for d in dnas if d is not None]
    if not dnas:
        return None
    while len(dnas) < len(SNAPSHOTS):
        dnas.append(dnas[-1])
    dna = torch.stack(dnas[: len(SNAPSHOTS)])

    g = model.graph_proj(dna.flatten().unsqueeze(0))
    stats = torch.from_numpy(extract_features(events[:n])).unsqueeze(0)
    stats = (stats - model.feat_mean) / (model.feat_std + 1e-6)
    s = model.stat_proj(torch.clamp(stats, -10, 10))
    return torch.cat([g, s], dim=1).squeeze(0).detach().numpy()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", type=Path, default=Path("data/traces"))
    ap.add_argument("--models", type=Path, default=Path("models"))
    ap.add_argument("--calib", type=int, default=120,
                    help="benign training traces used for calibration")
    args = ap.parse_args()

    model = HybridClassifier()
    model.load_state_dict(torch.load(args.models / "scbf_hybrid.pt", map_location="cpu"))
    model.eval()

    split = json.loads((args.models / "split_info.json").read_text())
    benign = [i for i in split["train"] if i["label"] == 0][: args.calib]
    print(f"Calibrating per-stage envelopes on {len(benign)} benign TRAINING installs")
    print(f"Checkpoints: {CHECKPOINTS}\n")

    sigs = {c: [] for c in CHECKPOINTS}
    with torch.no_grad():
        for k, it in enumerate(benign, 1):
            ev = load_events(it["path"])
            if not ev:
                continue
            for c in CHECKPOINTS:
                if len(ev) < c * 0.5:      # too short to be meaningful here
                    continue
                s = partial_signature(model, ev, c)
                if s is not None:
                    sigs[c].append(s)
            if k % 25 == 0:
                print(f"  {k}/{len(benign)}")

    env = {}
    print(f"\n  {'checkpoint':>11}{'n':>6}{'mean':>9}{'sd':>8}{'WARN':>9}{'BLOCK':>9}")
    for c in CHECKPOINTS:
        arr = np.array(sigs[c])
        if len(arr) < 20:
            print(f"  {c:>11}{len(arr):>6}   (too few samples — skipped)")
            continue
        cen = arr.mean(axis=0)
        d = np.linalg.norm(arr - cen, axis=1)
        mean, sd = float(d.mean()), float(d.std())
        env[str(c)] = {"centroid": cen.tolist(), "n": int(len(arr)),
                       "mean_distance": mean, "std_distance": sd,
                       "warn_threshold": mean + 1.5 * sd,
                       "block_threshold": mean + 2.5 * sd}
        print(f"  {c:>11}{len(arr):>6}{mean:>9.3f}{sd:>8.3f}"
              f"{mean + 1.5 * sd:>9.3f}{mean + 2.5 * sd:>9.3f}")

    out = args.models / "envelope_streaming.json"
    with open(out, "w") as f:
        json.dump({"checkpoints": list(CHECKPOINTS), "stages": env}, f)
    print(f"\nSaved: {out}")
    print("Validate with:  python3 -m scbf.detection.trajectory_staged")


if __name__ == "__main__":
    main()
