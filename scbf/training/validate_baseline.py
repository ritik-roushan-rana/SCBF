"""
How much should we believe the baseline test number?

Three checks that a single train/val/test table cannot answer:

  1. Cross-validation   - is 94.83% F1 a property of the model, or of the
                          one lucky split we happened to draw?
  2. Bootstrap CI       - the test set has 210 samples, 59 of them malicious.
                          One extra false negative moves recall ~1.7 points.
                          What is the actual confidence interval?
  3. Feature dominance  - r_writes carries 16x the permutation importance of
                          the next feature. Is that genuine behavior, or the
                          next proxy waiting to be found?

Usage:
    python3 -m scbf.training.validate_baseline --traces data/traces
"""

import argparse
import json
from pathlib import Path

import numpy as np

from scbf.features.statistical import extract_features, FEATURE_NAMES
from scbf.training.train import load_events


def build_matrix(items):
    X, y = [], []
    for it in items:
        ev = load_events(it["path"])
        if not ev:
            continue
        X.append(extract_features(ev))
        y.append(it["label"])
    return np.array(X), np.array(y)


def f1_at(p, y, thr):
    pred = p > thr
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return 2 * prec * rec / (prec + rec) if prec + rec else 0.0, prec, rec


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", type=Path, default=Path("data/traces"))
    ap.add_argument("--models", type=Path, default=Path("models"))
    args = ap.parse_args()

    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import roc_auc_score
    from scbf.dataset import ok_traces

    items = ok_traces(args.traces, require_manifest=False)
    print(f"Building features for {len(items)} traces...")
    X, y = build_matrix(items)
    print(f"  X={X.shape}  malicious={int(y.sum())}  benign={int((y==0).sum())}\n")

    # ---------------------------------------------------------------- 1
    print("=" * 74)
    print("1. CROSS-VALIDATION  (is the number split-dependent?)")
    print("=" * 74)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    f1s, aucs, precs, recs = [], [], [], []
    for k, (tr, te) in enumerate(skf.split(X, y), 1):
        m = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.06,
                                           class_weight="balanced", random_state=42)
        m.fit(X[tr], y[tr])
        p = m.predict_proba(X[te])[:, 1]
        f1, prec, rec = f1_at(p, y[te], 0.5)
        auc = roc_auc_score(y[te], p)
        f1s.append(f1); aucs.append(auc); precs.append(prec); recs.append(rec)
        print(f"  fold {k}:  F1={f1:.2%}  prec={prec:.2%}  rec={rec:.2%}  AUC={auc:.4f}")
    print(f"\n  MEAN F1  = {np.mean(f1s):.2%}  +/- {np.std(f1s):.2%} (sd)")
    print(f"  MEAN AUC = {np.mean(aucs):.4f} +/- {np.std(aucs):.4f}")
    print(f"  range    = {min(f1s):.2%} .. {max(f1s):.2%}")

    # ---------------------------------------------------------------- 2
    print("\n" + "=" * 74)
    print("2. BOOTSTRAP CI ON THE REPORTED TEST SPLIT")
    print("=" * 74)
    split_file = args.models / "split_info.json"
    if split_file.exists():
        sp = json.loads(split_file.read_text())
        Xtr, ytr = build_matrix(sp["train"])
        Xte, yte = build_matrix(sp["test"])
        m = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.06,
                                           class_weight="balanced", random_state=42)
        m.fit(Xtr, ytr)
        p = m.predict_proba(Xte)[:, 1]
        thr = json.loads((args.models / "baseline_results.json").read_text()) \
            .get("GRADIENT BOOSTING", {}).get("threshold", 0.5)
        base_f1, base_p, base_r = f1_at(p, yte, thr)
        print(f"  point estimate: F1={base_f1:.2%} prec={base_p:.2%} rec={base_r:.2%} "
              f"(n={len(yte)}, malicious={int(yte.sum())})")
        rng = np.random.default_rng(42)
        boot = []
        for _ in range(2000):
            idx = rng.integers(0, len(yte), len(yte))
            if y[idx].sum() == 0:
                continue
            boot.append(f1_at(p[idx], yte[idx], thr)[0])
        lo, hi = np.percentile(boot, [2.5, 97.5])
        print(f"  95% CI on F1  : [{lo:.2%}, {hi:.2%}]   width {hi-lo:.1%}")
        print(f"  -> with {int(yte.sum())} malicious test samples, one extra false")
        print(f"     negative moves recall by {1/yte.sum():.1%}")
    else:
        print("  (no split_info.json)")

    # ---------------------------------------------------------------- 3
    print("\n" + "=" * 74)
    print("3. FEATURE DOMINANCE  (is r_writes another proxy?)")
    print("=" * 74)
    i = FEATURE_NAMES.index("r_writes")
    c, mlw = X[y == 0, i], X[y == 1, i]
    print(f"  r_writes  benign   median={np.median(c):.4f}  IQR=[{np.percentile(c,25):.4f}, {np.percentile(c,75):.4f}]")
    print(f"  r_writes  malware  median={np.median(mlw):.4f}  IQR=[{np.percentile(mlw,25):.4f}, {np.percentile(mlw,75):.4f}]")
    overlap = max(0.0, min(c.max(), mlw.max()) - max(c.min(), mlw.min()))
    print(f"  ranges overlap: {'YES' if overlap > 0 else 'NO -- DISJOINT, investigate'}")
    print(f"  r_writes alone AUC = {max(roc_auc_score(y, X[:, i]), 1-roc_auc_score(y, X[:, i])):.4f}")

    m_all = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.06,
                                           class_weight="balanced", random_state=42)
    keep = [j for j in range(X.shape[1]) if j != i]
    scores = []
    for tr, te in skf.split(X, y):
        m_all.fit(X[tr][:, keep], y[tr])
        pp = m_all.predict_proba(X[te][:, keep])[:, 1]
        scores.append(f1_at(pp, y[te], 0.5)[0])
    print(f"\n  CV F1 WITHOUT r_writes = {np.mean(scores):.2%} "
          f"(vs {np.mean(f1s):.2%} with it)")
    print(f"  -> drop of {np.mean(f1s)-np.mean(scores):.2%}")
    print("     A small drop means the signal is spread across features (healthy).")
    print("     A large drop means one feature carries the model (fragile).")


if __name__ == "__main__":
    main()
