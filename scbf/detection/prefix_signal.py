"""
How much discriminative signal exists in the FIRST N events?

The earlier streaming test scored partial installs with a model trained on
complete traces, which is an unfair comparison: the partial signature is
out-of-distribution for that model, so a failure there does not prove the
signal is absent.

This measures the signal directly. For each prefix length N, features are
computed over the first N events ONLY, a classifier is trained on those
prefixes, and it is evaluated on held-out prefixes of the same length. The
resulting curve is the honest answer to "when does a malicious install become
distinguishable".

Gradient boosting is used rather than the TGN because it is seconds per point
instead of hours, and it establishes what is *available* in the prefix. If the
signal is not there for a strong tabular model, no amount of TGN training
recovers it; if it is there, the TGN is worth training on prefixes.

Ordering information is included explicitly: the statistical features already
carry first-connect and first-exec timing, burstiness and process depth.

Usage:
    python3 -m scbf.detection.prefix_signal --traces data/traces
"""

import argparse
import json
from pathlib import Path

import numpy as np

from scbf.dataset import ok_traces
from scbf.features.statistical import extract_features
from scbf.training.train import load_events, split_data

PREFIXES = (100, 250, 500, 750, 1000, 1500, 2000, 3000, None)   # None = full trace


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", type=Path, default=Path("data/traces"))
    ap.add_argument("--models", type=Path, default=Path("models"))
    args = ap.parse_args()

    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score

    split_file = args.models / "split_info.json"
    if split_file.exists():
        sp = json.loads(split_file.read_text())
        train, test = sp["train"], sp["test"]
    else:
        train, _, test = split_data(ok_traces(args.traces, require_manifest=False))

    print(f"train={len(train)}  test={len(test)}")
    print("Loading traces once, then truncating per prefix...\n")

    def load(items):
        out = []
        for it in items:
            ev = load_events(it["path"])
            if ev:
                out.append((ev, it["label"]))
        return out

    tr = load(train)
    te = load(test)
    print(f"loaded {len(tr)} train, {len(te)} test\n")

    print(f"  {'prefix':>8}{'n_train':>9}{'coverage':>10}{'precision':>11}"
          f"{'recall':>9}{'F1':>9}{'AUC':>9}")
    print("  " + "-" * 66)

    results = []
    for p in PREFIXES:
        # only traces long enough to actually HAVE this prefix
        trp = [(e[:p] if p else e, y) for e, y in tr if p is None or len(e) >= p]
        tep = [(e[:p] if p else e, y) for e, y in te if p is None or len(e) >= p]
        if len(trp) < 100 or len(tep) < 30:
            print(f"  {str(p or 'full'):>8}{len(trp):>9}   too few traces this long")
            continue

        Xtr = np.array([extract_features(e) for e, _ in trp])
        ytr = np.array([y for _, y in trp])
        Xte = np.array([extract_features(e) for e, _ in tep])
        yte = np.array([y for _, y in tep])

        m = HistGradientBoostingClassifier(max_iter=250, learning_rate=0.06,
                                           class_weight="balanced", random_state=42)
        m.fit(Xtr, ytr)
        prob = m.predict_proba(Xte)[:, 1]
        pred = prob > 0.5
        tp = int((pred & (yte == 1)).sum()); fp = int((pred & (yte == 0)).sum())
        fn = int((~pred & (yte == 1)).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        auc = roc_auc_score(yte, prob) if len(set(yte)) > 1 else float("nan")
        cov = len(tep) / len(te)

        print(f"  {str(p or 'full'):>8}{len(trp):>9}{cov:>9.0%}{prec:>11.2%}"
              f"{rec:>9.2%}{f1:>9.2%}{auc:>9.4f}")
        results.append((p, f1, auc, cov, prec, rec))

    print("\n" + "=" * 70)
    print("INTERPRETATION")
    print("=" * 70)
    if not results:
        print("  no usable prefixes")
        return
    full = [r for r in results if r[0] is None]
    base = full[0][1] if full else max(r[1] for r in results)
    print(f"  full-trace F1 (ceiling)            : {base:.2%}")
    for p, f1, auc, cov, prec, rec in results:
        if p is None:
            continue
        print(f"  first {p:>5} events  F1 {f1:>6.2%}  ({f1/base:>4.0%} of ceiling)"
              f"   covers {cov:.0%} of installs")
    early = [r for r in results if r[0] and r[0] <= 1000]
    if early:
        best = max(early, key=lambda r: r[1])
        print(f"\n  Best EARLY point: first {best[0]} events -> F1 {best[1]:.2%}, "
              f"AUC {best[2]:.4f}")
        if best[1] >= 0.80 * base:
            print("  => Early blocking is viable: most of the signal is present early,")
            print("     so a prefix-trained model can act before the install finishes.")
        else:
            print("  => Early blocking is NOT viable on this corpus: the prefix carries")
            print(f"     only {best[1]/base:.0%} of the full-trace signal. The difference")
            print("     between malicious and benign installs accumulates late.")


if __name__ == "__main__":
    main()
