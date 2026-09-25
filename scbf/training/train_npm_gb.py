"""
SCBF - NPM gradient-boosting detector.

A tree ensemble over the same feature vector the hybrid TGN model uses
(scbf/training/train_npm_hybrid.py). On the RQ1 NPM dataset it beats the
neural model by ~3 F1 points, so it is the recommended NPM detector; the
TGN model remains the architecture under study.

Model selection is done on the validation split only (config AND decision
threshold). The test split is scored exactly once with that choice, so the
reported numbers are not tuned on test.

Reads the preprocessing cache produced by train_npm_hybrid.py, so run that
first (or at least let it build the cache):

    python -m scbf.training.train_npm_hybrid --data-dir data/rq1_npm_rich --rich
    python -m scbf.training.train_npm_gb --rich

Outputs:
    models/scbf_npm_gb.joblib             model + threshold + config
    models/npm_gb_evaluation_results.json metrics (CV, validation, test)
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from scbf.training.train_npm_hybrid import SPLIT_FILE, cache_file  # noqa: E402

MODEL_OUTPUT = PROJECT_ROOT / "models" / "scbf_npm_gb.joblib"
RESULTS_FILE = PROJECT_ROOT / "models" / "npm_gb_evaluation_results.json"


def load_split(rich):
    import torch
    cache = torch.load(cache_file(rich), map_location="cpu", weights_only=False)
    by_path = {k.split("|")[0]: v for k, v in cache.items() if k != "_meta"}
    split = json.load(open(SPLIT_FILE))
    out = {}
    for name in ("train", "val", "test"):
        X, y, names = [], [], []
        for rel, label in split[name]:
            p = str(PROJECT_ROOT / rel)
            if p in by_path:
                X.append(by_path[p]["feats"])
                y.append(label)
                names.append(os.path.basename(rel))
        out[name] = (np.array(X), np.array(y), names)
    return out


def configs():
    from sklearn.ensemble import GradientBoostingClassifier, HistGradientBoostingClassifier
    for n in (400, 800):
        for d in (3, 4, 6):
            for lr in (0.05, 0.1):
                yield (f"GB n={n} d={d} lr={lr}",
                       lambda n=n, d=d, lr=lr: GradientBoostingClassifier(
                           n_estimators=n, max_depth=d, learning_rate=lr,
                           subsample=0.9, random_state=42))
    for lr in (0.05, 0.1):
        for leaves in (31, 63):
            yield (f"HistGB leaves={leaves} lr={lr}",
                   lambda lr=lr, leaves=leaves: HistGradientBoostingClassifier(
                       max_iter=500, learning_rate=lr, max_leaf_nodes=leaves,
                       l2_regularization=1.0, random_state=42))


def best_threshold(probs, y):
    from sklearn.metrics import f1_score
    return max(((float(t), f1_score(y, (probs > t).astype(int)))
                for t in np.arange(0.05, 0.96, 0.01)), key=lambda z: z[1])


def metrics(y, probs, thr):
    from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                                 recall_score, roc_auc_score)
    pred = (probs > thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred)),
        "f1": float(f1_score(y, pred)),
        "fpr": fp / max(1, fp + tn),
        "auc": float(roc_auc_score(y, probs)),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rich", action="store_true", help="use the rich-feature cache")
    ap.add_argument("--cv", action="store_true", help="also report 5-fold CV over all samples")
    args = ap.parse_args()

    import joblib
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    data = load_split(args.rich)
    (Xtr, ytr, _), (Xva, yva, _), (Xte, yte, names_te) = data["train"], data["val"], data["test"]
    print(f"train={len(ytr)} val={len(yva)} test={len(yte)}  features={Xtr.shape[1]}")

    print("\n=== selection on VALIDATION only ===")
    scored = []
    for name, make in configs():
        m = make().fit(Xtr, ytr)
        thr, vf1 = best_threshold(m.predict_proba(Xva)[:, 1], yva)
        scored.append((vf1, thr, name, make))
        print(f"  {name:28} val F1={vf1:.4f} thr={thr:.2f}", flush=True)

    vf1, thr, name, make = max(scored, key=lambda z: z[0])
    print(f"\nSELECTED: {name}   val F1={vf1:.4f}   threshold={thr:.2f}")

    # refit on train+val, score test exactly once
    X_full = np.vstack([Xtr, Xva]); y_full = np.concatenate([ytr, yva])
    model = make().fit(X_full, y_full)
    probs = model.predict_proba(Xte)[:, 1]
    tm = metrics(yte, probs, thr)
    vm = metrics(yva, make().fit(Xtr, ytr).predict_proba(Xva)[:, 1], thr)

    print("\n=== TEST (scored once) ===")
    for k in ("accuracy", "precision", "recall", "f1", "fpr", "auc"):
        print(f"{k.capitalize():10}: {tm[k]:.4f}")
    print(f"\n              Clean  Malicious\nActual Clean  {tm['tn']:5d}  {tm['fp']:5d}"
          f"\nActual Mal    {tm['fn']:5d}  {tm['tp']:5d}")

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset": "RQ1_NPM",
        "rich_features": args.rich,
        "feature_dim": int(Xtr.shape[1]),
        "selected_config": name,
        "threshold": thr,
        "validation": vm,
        "test": tm,
    }

    if args.cv:
        X_all = np.vstack([Xtr, Xva, Xte]); y_all = np.concatenate([ytr, yva, yte])
        cv = StratifiedKFold(5, shuffle=True, random_state=42)
        p = cross_val_predict(make(), X_all, y_all, cv=cv, method="predict_proba")[:, 1]
        cm = metrics(y_all, p, 0.5)
        print(f"\n=== 5-fold CV over all {len(y_all)} samples (threshold 0.50) ===")
        print(f"accuracy={cm['accuracy']:.4f} precision={cm['precision']:.4f} "
              f"recall={cm['recall']:.4f} f1={cm['f1']:.4f} auc={cm['auc']:.4f}")
        results["cross_validation_5fold"] = cm

    print("\nmissed malware (test):")
    for i in np.argsort(probs):
        if yte[i] == 1 and probs[i] <= thr:
            print(f"  {probs[i]:.3f}  {names_te[i]}")
    print("flagged benign (test):")
    for i in np.argsort(-probs):
        if yte[i] == 0 and probs[i] > thr:
            print(f"  {probs[i]:.3f}  {names_te[i]}")

    joblib.dump({"model": model, "threshold": thr, "config": name,
                 "feature_dim": int(Xtr.shape[1]), "rich": args.rich}, MODEL_OUTPUT)
    with open(RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nModel saved   -> {MODEL_OUTPUT}")
    print(f"Results saved -> {RESULTS_FILE}")


if __name__ == "__main__":
    main()
