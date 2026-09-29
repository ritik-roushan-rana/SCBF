"""
Is mid-install blocking actually possible?

Streaming enforcement only has value if the behavioural signature crosses the
BLOCK threshold BEFORE the install finishes. If malware only becomes
distinguishable at the last event, a streaming verdict saves nothing over the
post-install gate.

This replays captured traces event by event, tracks the PURE (128-dim) DNA
distance from the benign centroid, and reports at what fraction of the install
each trace would first have been blocked.

The pure embodiment is used because it needs no snapshot schedule: a valid
128-dim signature exists after every event. The fused 192-dim representation
depends on 8 checkpoints of a COMPLETE trace and so cannot be computed mid-run.

Usage:
    python3 -m scbf.detection.trajectory --models models --n 12
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from scbf.training.train import HybridClassifier, load_events


def trajectory(model, events, centroid, block_thr, warn_thr, step=100):
    """Replay a trace, returning (fraction_of_install, distance) samples."""
    model.itbg.reset()
    out = []
    first_block = None
    for i, e in enumerate(events, 1):
        dna = model.itbg.add_event(e)
        if dna is None or i % step:
            continue
        d = float(np.linalg.norm(dna.detach().numpy() - centroid))
        frac = i / len(events)
        out.append((frac, d))
        if first_block is None and d >= block_thr:
            first_block = (frac, i, d)
    return out, first_block


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", type=Path, default=Path("models"))
    ap.add_argument("--traces", type=Path, default=Path("data/traces"))
    ap.add_argument("--n", type=int, default=12, help="traces per class")
    ap.add_argument("--step", type=int, default=100)
    args = ap.parse_args()

    model = HybridClassifier()
    model.load_state_dict(torch.load(args.models / "scbf_hybrid.pt", map_location="cpu"))
    model.eval()

    env = json.loads((args.models / "envelope.json").read_text())["pure"]
    centroid = np.array(env["centroid"])
    warn, block = env["warn_threshold"], env["block_threshold"]
    print(f"PURE envelope: mean {env['mean_distance']:.4f}  sd {env['std_distance']:.4f}")
    print(f"               WARN >= {warn:.4f}   BLOCK >= {block:.4f}\n")

    split = json.loads((args.models / "split_info.json").read_text())
    mal = [i for i in split["test"] if i["label"] == 1][: args.n]
    ben = [i for i in split["test"] if i["label"] == 0][: args.n]

    results = {}
    for label, items in (("MALICIOUS", mal), ("BENIGN", ben)):
        print(f"=== {label} ===")
        print(f"  {'package':<34}{'events':>8}{'blocked at':>12}{'final d':>10}")
        rows = []
        for it in items:
            ev = load_events(it["path"])
            if not ev:
                continue
            with torch.no_grad():
                traj, fb = trajectory(model, ev, centroid, block, warn, args.step)
            if not traj:
                continue
            final = traj[-1][1]
            name = Path(it["path"]).stem[:32]
            when = f"{fb[0]:.0%} (ev {fb[1]})" if fb else "never"
            print(f"  {name:<34}{len(ev):>8}{when:>12}{final:>10.3f}")
            rows.append((fb[0] if fb else None, final))
        results[label] = rows
        print()

    print("=" * 66)
    print("FEASIBILITY OF MID-INSTALL BLOCKING")
    print("=" * 66)
    for label in ("MALICIOUS", "BENIGN"):
        rows = results.get(label, [])
        if not rows:
            continue
        blocked = [r[0] for r in rows if r[0] is not None]
        print(f"\n{label}: {len(blocked)}/{len(rows)} would be blocked at some point")
        if blocked:
            print(f"  earliest block at {min(blocked):.0%} of the install")
            print(f"  median  block at {np.median(blocked):.0%}")
            early = sum(1 for b in blocked if b <= 0.5)
            print(f"  blocked in the first half: {early}/{len(blocked)}")

    mb = [r[0] for r in results.get("MALICIOUS", []) if r[0] is not None]
    bb = [r[0] for r in results.get("BENIGN", []) if r[0] is not None]
    print("\nVERDICT:")
    if not mb:
        print("  Mid-install blocking is NOT viable with this envelope: no malicious")
        print("  trace crosses the BLOCK threshold at any point during replay.")
    elif bb:
        print(f"  {len(bb)} benign trace(s) also cross BLOCK mid-install — streaming")
        print("  enforcement would cause false positives that the post-install")
        print("  verdict does not. The threshold needs recalibrating for streaming.")
    else:
        print("  Viable: malicious traces cross BLOCK mid-install and benign ones")
        print("  never do, so the installer can be terminated before completion.")


if __name__ == "__main__":
    main()
