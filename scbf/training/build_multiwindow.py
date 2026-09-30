"""Fit the shipped PyPI blocker: TGN ensemble + multi-window gradient boosting.

Why multi-window. A fixed 3000-event decision point is reached by only 59% of
installs. The rest finish first and are judged after the payload has already
run, which is detection wearing a blocking label -- measured live, packages
like pyghoster and eepl completed in ~2600 events and were only flagged at the
end. Scoring at several points lets short installs be terminated mid-flight.

The TGN members must be --random-window trained: a fixed-prefix model is
out-of-distribution at every other window, which is exactly why scoring short
installs returned p=0.0001 on known malware.

The GBM stage is fitted across all windows at once with the window size as an
input, so it calibrates instead of assuming a trace length, and each decision
point gets its own threshold tuned on VALIDATION.

Usage:
    python3 -m scbf.training.build_multiwindow \
        --traces data/pip_traces --tgn models_pypi --out models_pypi
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import torch
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (f1_score, precision_score, recall_score,
                             roc_auc_score)

import scbf.features.statistical as S
from scbf.envelope.streaming import partial_signature
from scbf.training.train import HybridClassifier, load_events, set_prefix

SEEDS = ("seed42", "seed7", "seed1337")


def load_members(root: Path):
    ms = []
    for d in SEEDS:
        m = HybridClassifier()
        m.load_state_dict(torch.load(root / d / "scbf_hybrid.pt",
                                     map_location="cpu"))
        m.eval()
        ms.append(m)
    return ms


def rows(models, items, window):
    """[TGN ensemble score] + 51 statistical features + [window]."""
    set_prefix(window)
    X, Y = [], []
    for it in items:
        ev = load_events(it["path"])
        if not ev:
            continue
        ps = []
        with torch.no_grad():
            for m in models:
                sig = partial_signature(m, ev, min(window, len(ev)))
                if sig is None:
                    ps = []
                    break
                ps.append(float(torch.sigmoid(
                    m.head(torch.tensor(sig).unsqueeze(0))).squeeze()))
        if not ps:
            continue
        X.append(np.concatenate([[np.mean(ps)],
                                 S.extract_features(ev), [window]]))
        Y.append(it["label"])
    return np.array(X), np.array(Y)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tgn", type=Path, default=Path("models_pypi"),
                    help="directory holding seed42/seed7/seed1337")
    ap.add_argument("--out", type=Path, default=Path("models_pypi"))
    ap.add_argument("--windows", type=int, nargs="+", default=[1500, 2200, 3000])
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 7, 1337])
    args = ap.parse_args()

    split = json.loads((args.tgn / "split_info.json").read_text())
    models = load_members(args.tgn)

    data = {}
    for w in args.windows:
        for sp in ("train", "val", "test"):
            data[(sp, w)] = rows(models, split[sp], w)
            print(f"  {sp} @{w}: {len(data[(sp, w)][1])}", flush=True)

    Xtr = np.vstack([data[("train", w)][0] for w in args.windows])
    Ytr = np.concatenate([data[("train", w)][1] for w in args.windows])
    gbms = [HistGradientBoostingClassifier(max_iter=300, class_weight="balanced",
                                           random_state=s).fit(Xtr, Ytr)
            for s in args.seeds]
    print(f"\nGBM fitted on {len(Ytr)} rows across {len(args.windows)} windows\n")

    thresholds, report = {}, {}
    print(f"{'window':>8}{'thr':>9}{'prec':>10}{'rec':>9}{'F1':>9}{'AUC':>9}")
    for w in args.windows:
        Xv, Yv = data[("val", w)]
        Xt, Yt = data[("test", w)]
        pv = np.mean([g.predict_proba(Xv)[:, 1] for g in gbms], axis=0)
        pt = np.mean([g.predict_proba(Xt)[:, 1] for g in gbms], axis=0)
        # threshold from VALIDATION only, then test is scored once
        t = float(max(np.unique(pv), key=lambda x: f1_score(Yv, pv >= x)))
        thresholds[w] = t
        report[str(w)] = {"n": int(len(Yt)),
                          "precision": float(precision_score(Yt, pt >= t, zero_division=0)),
                          "recall": float(recall_score(Yt, pt >= t)),
                          "f1": float(f1_score(Yt, pt >= t)),
                          "roc_auc": float(roc_auc_score(Yt, pt))}
        r = report[str(w)]
        print(f"{w:>8}{t:>9.4f}{r['precision']:>10.2%}{r['recall']:>9.2%}"
              f"{r['f1']:>9.2%}{r['roc_auc']:>9.4f}")

    args.out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"gbms": gbms, "thresholds": thresholds,
                 "windows": list(args.windows), "tgn_seeds": list(SEEDS),
                 "feature_order": "[tgn_score] + 51 statistical + [window]"},
                args.out / "multiwindow_gbm.joblib")
    print(f"\nSaved: {args.out / 'multiwindow_gbm.joblib'}")
    print("OSCAR PyPI baseline: precision 99.00%  recall 85.00%  F1 91.00%")


if __name__ == "__main__":
    main()
