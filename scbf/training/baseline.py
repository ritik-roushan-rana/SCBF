"""
Tabular baselines on the 51 statistical features.

This is the bar the TGN has to clear. If a logistic regression or a
gradient-boosted tree on plain features matches the temporal graph model,
the graph is not earning its parameters and you should ship the simple
model -- it is smaller, faster and interpretable.

Uses the SAME split file the TGN uses, so the comparison is exact. The
threshold is tuned on val only, and test is scored once.

Usage:
    python3 -m scbf.training.baseline --traces data/traces
"""

import argparse
import json
from pathlib import Path

import numpy as np

from scbf.features.statistical import extract_features, FEATURE_NAMES
from scbf.training.train import discover, split_data, load_events


def matrix(items):
    X, y = [], []
    for it in items:
        ev = load_events(it["path"])
        if not ev:
            continue
        X.append(extract_features(ev))
        y.append(it["label"])
    return np.array(X), np.array(y)


def metrics(p, y, thr):
    from sklearn.metrics import roc_auc_score
    pred = p > thr
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum()); tn = int((~pred & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    try:
        auc = float(roc_auc_score(y, p))
    except Exception:
        auc = float("nan")
    return dict(n=len(y), accuracy=(tp + tn) / max(1, len(y)), precision=prec,
                recall=rec, f1=f1, roc_auc=auc, tp=tp, fn=fn, fp=fp, tn=tn)


def report(name, model, sets, thr):
    print(f"\n{name}")
    print(f"  {'split':<7}{'n':>7}{'acc':>9}{'prec':>9}{'rec':>9}{'f1':>9}{'auc':>9}   confusion")
    out = {}
    for split, (X, y) in sets.items():
        p = model.predict_proba(X)[:, 1]
        m = metrics(p, y, thr)
        out[split] = m
        print(f"  {split:<7}{m['n']:>7}{m['accuracy']:>8.2%}{m['precision']:>9.2%}"
              f"{m['recall']:>8.2%}{m['f1']:>8.2%}{m['roc_auc']:>9.4f}   "
              f"TP {m['tp']:<4} FN {m['fn']:<4} FP {m['fp']:<4} TN {m['tn']:<4}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", type=Path, default=Path("data/traces"))
    ap.add_argument("--models", type=Path, default=Path("models"))
    args = ap.parse_args()

    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler

    split_file = args.models / "split_info.json"
    if split_file.exists():
        split = json.loads(split_file.read_text())
        train, val, test = split["train"], split["val"], split["test"]
        print(f"Using existing split: {split_file}")
    else:
        train, val, test = split_data(discover(args.traces))
        args.models.mkdir(parents=True, exist_ok=True)
        with open(split_file, "w") as f:
            json.dump({"train": train, "val": val, "test": test, "seed": 42}, f, indent=2)
        print(f"Wrote split: {split_file}")

    print("Extracting features...")
    Xtr, ytr = matrix(train); Xva, yva = matrix(val); Xte, yte = matrix(test)
    print(f"  train={Xtr.shape}  val={Xva.shape}  test={Xte.shape}")
    print(f"  malicious: train={int(ytr.sum())} val={int(yva.sum())} test={int(yte.sum())}")

    sc = StandardScaler().fit(Xtr)
    results = {}

    for name, model, use_scaled in (
        ("LOGISTIC REGRESSION", LogisticRegression(max_iter=5000, class_weight="balanced"), True),
        ("GRADIENT BOOSTING", HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.06, class_weight="balanced", random_state=42), False),
    ):
        A, B, C = (sc.transform(Xtr), sc.transform(Xva), sc.transform(Xte)) if use_scaled \
            else (Xtr, Xva, Xte)
        model.fit(A, ytr)
        pv = model.predict_proba(B)[:, 1]
        thr = max(np.arange(0.20, 0.85, 0.05), key=lambda t: metrics(pv, yva, float(t))["f1"])
        print(f"\n[{name}] threshold tuned on val: {thr:.2f}")
        results[name] = report(name, model, {"train": (A, ytr), "val": (B, yva),
                                             "test": (C, yte)}, float(thr))
        results[name]["threshold"] = float(thr)

        if name == "GRADIENT BOOSTING":
            try:
                from sklearn.inspection import permutation_importance
                imp = permutation_importance(model, C, yte, n_repeats=5,
                                             random_state=42, scoring="roc_auc")
                order = np.argsort(imp.importances_mean)[::-1][:12]
                print("\n  Top features by permutation importance (test):")
                for i in order:
                    nm = FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f"feat_{i}"
                    print(f"    {nm:<22}{imp.importances_mean[i]:+.4f}")
            except Exception as exc:
                print(f"  (importance unavailable: {exc})")

    out = args.models / "baseline_results.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2, default=float)
    print(f"\nSaved: {out}")
    best = max(results.items(), key=lambda kv: kv[1]["test"]["f1"])
    print(f"\nBAR FOR THE TGN: {best[0]} test F1 = {best[1]['test']['f1']:.2%}, "
          f"AUC = {best[1]['test']['roc_auc']:.4f}")
    print("If the hybrid TGN does not beat this, ship the tabular model instead.")


if __name__ == "__main__":
    main()
