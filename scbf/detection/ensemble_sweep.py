"""
Sweep the install-time block threshold using a MULTI-WINDOW ensemble.

The single-window sweep underuses a window-invariant model. v6 was trained on
random prefixes, so it produces a usable score at every window -- averaging
those scores cancels the per-window variance that made single-window verdicts
flip between captures, and usually sharpens the decision as well.

Each trace is scored at every window it is long enough to reach, the scores are
combined, and the threshold is swept over the combination. Both the mean and
the max are reported: the mean is stabler, the max catches malware that only
reveals itself at one stage of the install.

Usage:
    python3 -m scbf.detection.ensemble_sweep --models models_v6
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from scbf.envelope.streaming import partial_signature
from scbf.training.train import HybridClassifier, load_events, set_prefix

WINDOWS = (1500, 2000, 2500, 3000)


def collect(model, items):
    rows = []
    with torch.no_grad():
        for it in items:
            ev = load_events(it["path"])
            if not ev:
                continue
            ps = []
            for w in WINDOWS:
                if len(ev) < w * 0.8:
                    continue
                sig = partial_signature(model, ev, min(w, len(ev)))
                if sig is None:
                    continue
                ps.append(float(torch.sigmoid(
                    model.head(torch.tensor(sig).unsqueeze(0))).squeeze()))
            if ps:
                rows.append((float(np.mean(ps)), float(np.max(ps)),
                             it["label"], len(ev)))
    return rows


def sweep(rows, idx, name, target_f1=0.91):
    mal = [r for r in rows if r[2] == 1]
    ben = [r for r in rows if r[2] == 0]
    best = None
    out = []
    for t in sorted({r[idx] for r in rows}):
        tp = sum(1 for r in mal if r[idx] >= t)
        fp = sum(1 for r in ben if r[idx] >= t)
        fn = len(mal) - tp
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        fpr = fp / max(1, len(ben))
        out.append((t, rec, fpr, prec, f1))
        if best is None or f1 > best[4]:
            best = (t, rec, fpr, prec, f1)

    print(f"\n  === {name} ===")
    print(f"  {'threshold':>10}{'blocked':>10}{'false kills':>13}{'precision':>11}{'F1':>8}")
    for budget in (0.01, 0.02, 0.05, 0.10):
        ok = [o for o in out if o[2] <= budget]
        if ok:
            b = max(ok, key=lambda o: o[1])
            print(f"  {b[0]:>10.3f}{b[1]:>9.1%}{b[2]:>12.1%}{b[3]:>11.1%}{b[4]:>8.1%}"
                  f"   <= {budget:.0%} FP")
    print(f"  {best[0]:>10.3f}{best[1]:>9.1%}{best[2]:>12.1%}{best[3]:>11.1%}"
          f"{best[4]:>8.1%}   <- best F1")

    beat = [o for o in out if o[4] > target_f1 and o[1] > 0.85]
    if beat:
        b = max(beat, key=lambda o: o[4])
        print(f"\n  BEATS OSCAR (F1>{target_f1:.0%}, recall>85%): "
              f"thr={b[0]:.3f} F1={b[4]:.1%} prec={b[3]:.1%} rec={b[1]:.1%} "
              f"fp={b[2]:.1%}")
    else:
        print(f"\n  does not beat OSCAR on this signal "
              f"(best F1 {best[4]:.1%}, recall {best[1]:.1%})")
    return best


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", type=Path, default=Path("models_v6"))
    args = ap.parse_args()

    set_prefix(0)          # windows are applied explicitly per score
    model = HybridClassifier()
    model.load_state_dict(torch.load(args.models / "scbf_hybrid.pt",
                                     map_location="cpu"))
    model.eval()
    split = json.loads((args.models / "split_info.json").read_text())

    print(f"Multi-window ensemble over {WINDOWS}")
    print("Scoring held-out test traces at every reachable window...")
    rows = collect(model, split["test"])
    mal = sum(1 for r in rows if r[2] == 1)
    print(f"  {len(rows)} traces ({mal} malicious, {len(rows)-mal} benign)")
    print("\nOSCAR baseline: precision 0.99, recall 0.85, F1 0.91")

    sweep(rows, 0, "MEAN across windows")
    sweep(rows, 1, "MAX across windows")


if __name__ == "__main__":
    main()
