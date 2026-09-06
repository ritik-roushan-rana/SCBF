"""
Standalone eval for the pure-TGN checkpoint saved by train_tgn_pure.py.

Loads models/checkpoints/tgn_pure_best.pt, reconstructs the same 70/15/15
split, tunes the classifier threshold on val, and reports train/val/test
metrics — same methodology as scbf.training.evaluate but for the pure-TGN
architecture.
"""

import os
import sys
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).parent.parent))

from scbf.training.train_hybrid_v2 import (
    FocalBCELoss,
    compute_metrics,
    load_events,
    set_seed,
    split_data,
)
from scbf.training.train_tgn_pure import PureTGNClassifier


CKPT = "models/checkpoints/tgn_pure_best.pt"


def score(model, dataset, threshold: float):
    model.eval()
    logits_list, labels_list = [], []
    with torch.no_grad():
        for path, label in dataset:
            try:
                events = load_events(path)
                _, logits = model(events)
                if logits is None:
                    continue
                logits_list.append(logits.squeeze())
                labels_list.append(float(label))
            except Exception:
                continue

    if not logits_list:
        return None

    logits = torch.stack(logits_list)
    labels = torch.tensor(labels_list)
    m = compute_metrics(logits, labels, threshold=threshold)

    try:
        from sklearn.metrics import roc_auc_score
        m["roc_auc"] = float(roc_auc_score(labels.numpy(), torch.sigmoid(logits).numpy()))
    except Exception:
        m["roc_auc"] = None

    return m


def main() -> None:
    import glob

    set_seed(42)
    clean = glob.glob("data/zenodo_13746167/benign/traces/*.jsonl")
    mal = glob.glob("data/zenodo_13746167/malware/traces/*.jsonl")

    train_set, val_set, test_set = split_data(clean, mal, seed=42)
    print(f"Split: train={len(train_set)}  val={len(val_set)}  test={len(test_set)}")

    if not os.path.exists(CKPT):
        print(f"❌ No checkpoint at {CKPT}. Run: make train-tgn-pure")
        return

    print(f"Loading {CKPT}...")
    model = PureTGNClassifier(num_nodes=50000)
    model.load_state_dict(torch.load(CKPT, map_location="cpu"))
    model.eval()

    # Threshold search on val
    print("\nSearching best threshold on val...")
    best_t, best_f1 = 0.5, 0.0
    for t in np.arange(0.15, 0.85, 0.025):
        m = score(model, val_set, threshold=float(t))
        if m and m["f1"] > best_f1:
            best_f1, best_t = m["f1"], float(t)
    print(f"  best_threshold = {best_t:.3f}   (val F1 = {best_f1:.2%})")

    # Score all three splits
    print("\nScoring all splits at that threshold...")
    results = {}
    for name, ds in [("train", train_set[:300]), ("val", val_set), ("test", test_set)]:
        # train is capped at 300 to keep this quick — that's already 3x val/test.
        print(f"  {name}: {len(ds)} samples...")
        results[name] = score(model, ds, threshold=best_t)

    print("\n" + "=" * 78)
    print(f"PURE-TGN RESULTS   (threshold={best_t:.3f})")
    print("=" * 78)
    for name in ("train", "val", "test"):
        r = results[name]
        auc = f"{r['roc_auc']:.4f}" if r["roc_auc"] is not None else "n/a"
        cm = r
        print(f"\n{name.upper():<6} n={r['n_samples']}  "
              f"(clean {r['n_clean']}, mal {r['n_malicious']})")
        print(f"  Accuracy  = {r['accuracy']:.2%}")
        print(f"  Precision = {r['precision']:.2%}")
        print(f"  Recall    = {r['recall']:.2%}")
        print(f"  F1        = {r['f1']:.2%}")
        print(f"  ROC-AUC   = {auc}")
        print(f"  Conf      TP {cm['tp']:>3}  FN {cm['fn']:>3}")
        print(f"            FP {cm['fp']:>3}  TN {cm['tn']:>3}")
    print("=" * 78)


if __name__ == "__main__":
    main()
