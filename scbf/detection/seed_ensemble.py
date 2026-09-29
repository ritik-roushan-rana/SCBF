"""
Multi-seed ensemble for install-time blocking.

A single training run of a 460k-parameter model on 974 samples carries real
seed variance: the same configuration lands a point or two either side of its
mean depending on initialisation. Averaging the predictions of several seeds
removes that variance and is standard practice -- it is not test-set fishing,
because no test information selects the members.

The threshold is tuned on VALIDATION, then applied once to test.

Usage:
    python3 -m scbf.detection.seed_ensemble --models models_v5 models_v5b models_v5c --at 3000
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from scbf.envelope.streaming import partial_signature
from scbf.training.train import HybridClassifier, load_events, set_prefix

OSCAR = {"precision": 0.99, "recall": 0.85, "f1": 0.91}


def scores(model, items, at):
    P, Y = [], []
    with torch.no_grad():
        for it in items:
            ev = load_events(it["path"])
            if not ev:
                continue
            s = partial_signature(model, ev, at)
            if s is None:
                continue
            P.append(float(torch.sigmoid(
                model.head(torch.tensor(s).unsqueeze(0))).squeeze()))
            Y.append(it["label"])
    return np.array(P), np.array(Y)


def metrics(P, Y, t):
    from sklearn.metrics import roc_auc_score
    pred = P >= t
    nm = int(Y.sum())
    tp = int((pred & (Y == 1)).sum()); fp = int((pred & (Y == 0)).sum())
    fn = nm - tp; tn = len(Y) - nm - fp
    prec = tp / max(1, tp + fp); rec = tp / max(1, nm)
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    try:
        auc = roc_auc_score(Y, P)
    except Exception:
        auc = float("nan")
    return dict(n=len(Y), accuracy=(tp + tn) / len(Y), precision=prec,
                recall=rec, f1=f1, roc_auc=auc, tp=tp, fn=fn, fp=fp, tn=tn)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--at", type=int, default=3000)
    args = ap.parse_args()

    set_prefix(args.at)
    split = json.loads((Path(args.models[0]) / "split_info.json").read_text())

    val_P, test_P = [], []
    for d in args.models:
        m = HybridClassifier()
        m.load_state_dict(torch.load(Path(d) / "scbf_hybrid.pt", map_location="cpu"))
        m.eval()
        pv, Yv = scores(m, split["val"], args.at)
        pt, Yt = scores(m, split["test"], args.at)
        val_P.append(pv); test_P.append(pt)
        print(f"  {d}: val F1 {max((metrics(pv,Yv,t)['f1'] for t in np.arange(0.1,0.95,0.05))):.2%}")

    Pv = np.mean(val_P, axis=0)
    Pt = np.mean(test_P, axis=0)

    # threshold chosen on VALIDATION only, for best F1
    thr = max(sorted(set(Pv)), key=lambda t: metrics(Pv, Yv, t)["f1"])
    print(f"\nEnsemble of {len(args.models)} seeds, decision at event {args.at}")
    print(f"threshold tuned on VALIDATION: {thr:.4f}\n")
    print(f"  {'split':<6}{'n':>5}{'acc':>9}{'prec':>10}{'rec':>9}{'F1':>9}{'AUC':>9}   confusion")
    out = {}
    for nm, P, Y in (("val", Pv, Yv), ("test", Pt, Yt)):
        r = metrics(P, Y, thr); out[nm] = r
        print(f"  {nm:<6}{r['n']:>5}{r['accuracy']:>8.2%}{r['precision']:>10.2%}"
              f"{r['recall']:>9.2%}{r['f1']:>9.2%}{r['roc_auc']:>9.4f}   "
              f"TP{r['tp']} FN{r['fn']} FP{r['fp']} TN{r['tn']}")

    t = out["test"]
    print(f"\n  vs OSCAR (precision 99.00%, recall 85.00%, F1 91.00%):")
    for k, label in (("precision", "precision"), ("recall", "recall"), ("f1", "F1")):
        d = t[k] - OSCAR[k]
        print(f"    {label:<10}{t[k]:>8.2%}   {d:+.2%}  {'BEATS' if d > 0 else 'below'}")
    if t["recall"] > OSCAR["recall"] and t["f1"] > OSCAR["f1"]:
        print("\n  *** BEATS OSCAR ON RECALL AND F1 ***")


if __name__ == "__main__":
    main()
