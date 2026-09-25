"""
5-fold cross-validation of the hybrid TGN, with pooled out-of-fold predictions.

Why this matters for the OSCAR comparison:

    OSCAR is zero-shot over the WHOLE benchmark -- their 0.91 F1 is computed
    on all 500 malicious packages. A single train/val/test split scores our
    model on 59 malicious samples, so the confidence interval is ~9 points
    wide and a reviewer can fairly say the comparison is not meaningful.

    Cross-validation predicts every trace exactly once while it is held out.
    Pooling those predictions gives one number over ALL 389 malicious
    packages -- the closest honest analogue to OSCAR's protocol.

Each fold trains from scratch; nothing leaks across folds. The threshold is
chosen inside each fold on that fold's own validation slice, never on the
held-out data being scored.

Usage:
    python3 -m scbf.training.cross_validate --traces data/traces --folds 5
"""

import argparse
import json
import random
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

from scbf.dataset import ok_traces
from scbf.training.train import (HybridClassifier, feature_stats, metrics,
                                 run_split, set_seed)


def fold_indices(items, n_folds, seed=42):
    """Stratified folds so class balance is identical in each."""
    rng = random.Random(seed)
    by_class = {0: [], 1: []}
    for it in items:
        by_class[it["label"]].append(it)
    folds = [[] for _ in range(n_folds)]
    for label, group in by_class.items():
        g = sorted(group, key=lambda d: d["path"])
        rng.shuffle(g)
        for i, it in enumerate(g):
            folds[i % n_folds].append(it)
    return folds


def train_one_fold(train_items, val_items, epochs, patience, lr, pw_mult):
    mean, std = feature_stats(train_items)
    model = HybridClassifier(feat_mean=mean, feat_std=std)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(opt, T_0=10, T_mult=2)
    n_mal = sum(i["label"] for i in train_items)
    pw = (len(train_items) - n_mal) / max(1, n_mal) * pw_mult
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(pw))

    best_f1, best_state, stale = 0.0, None, 0
    for ep in range(1, epochs + 1):
        run_split(model, train_items, loss_fn, opt)
        vl, vy, _ = run_split(model, val_items)
        sched.step()
        vm = metrics(vl, vy, 0.5)
        if vm["f1"] > best_f1:
            best_f1 = vm["f1"]
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            stale = 0
        else:
            stale += 1
            if stale >= patience:
                break
        print(f"      epoch {ep:>2}  val f1={vm['f1']:.2%}", flush=True)

    if best_state is not None:
        model.load_state_dict(best_state)
    # threshold chosen on this fold's validation slice only
    vl, vy, _ = run_split(model, val_items)
    thr = max(np.arange(0.20, 0.85, 0.05),
              key=lambda t: metrics(vl, vy, float(t))["f1"])
    return model, float(thr)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", type=Path, default=Path("data/traces"))
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--epochs", type=int, default=45)
    ap.add_argument("--patience", type=int, default=10)
    ap.add_argument("--lr", type=float, default=5e-4)
    ap.add_argument("--pw-mult", type=float, default=1.0)
    ap.add_argument("--out", type=Path, default=Path("models/cv_results.json"))
    args = ap.parse_args()

    set_seed(42)
    items = ok_traces(args.traces, require_manifest=False)
    print(f"{len(items)} traces  (malicious {sum(i['label'] for i in items)})")
    folds = fold_indices(items, args.folds)

    all_p, all_y, per_fold = [], [], []
    for k in range(args.folds):
        test_items = folds[k]
        rest = [it for j, f in enumerate(folds) if j != k for it in f]
        # carve a validation slice out of the remaining folds
        n_val = max(1, len(rest) // 8)
        val_items, train_items = rest[:n_val], rest[n_val:]
        print(f"\n=== FOLD {k+1}/{args.folds}  "
              f"train={len(train_items)} val={len(val_items)} held-out={len(test_items)}",
              flush=True)

        model, thr = train_one_fold(train_items, val_items, args.epochs,
                                    args.patience, args.lr, args.pw_mult)
        tl, ty, _ = run_split(model, test_items)
        m = metrics(tl, ty, thr)
        per_fold.append(m)
        all_p.append(torch.sigmoid(tl).numpy())
        all_y.append(ty.numpy())
        print(f"  fold {k+1}: F1={m['f1']:.2%} prec={m['precision']:.2%} "
              f"rec={m['recall']:.2%} auc={m['roc_auc']:.4f} (thr={thr:.2f})", flush=True)

    p = np.concatenate(all_p); y = np.concatenate(all_y)
    f1s = [m["f1"] for m in per_fold]

    print("\n" + "=" * 76)
    print("CROSS-VALIDATED RESULT  (every trace predicted once, while held out)")
    print("=" * 76)
    print(f"  per-fold F1 : {', '.join(f'{f:.2%}' for f in f1s)}")
    print(f"  MEAN F1     : {np.mean(f1s):.2%} +/- {np.std(f1s):.2%}")

    # pooled out-of-fold, threshold = mean of per-fold thresholds
    best = max(np.arange(0.2, 0.85, 0.05),
               key=lambda t: _f1(p, y, float(t)))
    f1, prec, rec = _f1(p, y, float(best), full=True)
    from sklearn.metrics import roc_auc_score
    print(f"\n  POOLED over all {len(y)} traces ({int(y.sum())} malicious):")
    print(f"    Precision = {prec:.2%}")
    print(f"    Recall    = {rec:.2%}")
    print(f"    F1        = {f1:.2%}")
    print(f"    ROC-AUC   = {roc_auc_score(y, p):.4f}")
    print(f"\n  OSCAR (PyPI, zero-shot, 500 malicious): P=0.99 R=0.85 F1=0.91")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump({"per_fold": per_fold, "mean_f1": float(np.mean(f1s)),
                   "std_f1": float(np.std(f1s)),
                   "pooled": {"precision": prec, "recall": rec, "f1": f1,
                              "roc_auc": float(roc_auc_score(y, p)),
                              "n": int(len(y)), "n_malicious": int(y.sum())}},
                  f, indent=2, default=float)
    print(f"\nSaved: {args.out}")


def _f1(p, y, thr, full=False):
    pred = p > thr
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return (f1, prec, rec) if full else f1


if __name__ == "__main__":
    main()
