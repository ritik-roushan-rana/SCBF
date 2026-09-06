"""
Evaluate the trained hybrid model on the train / val / test splits and save
a persistent metrics report.

Run:
    make evaluate

Outputs:
    models/evaluation_results.json   — machine-readable metrics per split
    prints a human-readable table to stdout

The split is loaded from models/checkpoints/split_info.json (written by
train_hybrid_v2.py), so the numbers are always over the exact same held-out
sets the model was trained on.
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).parent.parent))

from training.train_hybrid_v2 import HybridClassifierV2, load_events


# ─────────────────────────────────────────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────────────────────────────────────────

def compute_metrics(logits: torch.Tensor, labels: torch.Tensor, threshold: float = 0.35) -> dict:
    """Standard binary classification metrics + confusion matrix."""
    probs = torch.sigmoid(logits)
    preds = (probs > threshold).long()
    y = labels.long()

    tp = int(((preds == 1) & (y == 1)).sum())
    tn = int(((preds == 0) & (y == 0)).sum())
    fp = int(((preds == 1) & (y == 0)).sum())
    fn = int(((preds == 0) & (y == 1)).sum())

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0

    # AUC (nice to have; needs sklearn but degrades gracefully)
    auc = None
    try:
        from sklearn.metrics import roc_auc_score
        auc = float(roc_auc_score(y.numpy(), probs.numpy()))
    except Exception:
        pass

    return {
        "threshold": threshold,
        "n_samples": total,
        "n_clean": tn + fp,
        "n_malicious": tp + fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "roc_auc": auc,
        "confusion_matrix": {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Evaluation over a split
# ─────────────────────────────────────────────────────────────────────────────

def score_split(model: HybridClassifierV2, split: list) -> tuple[torch.Tensor, torch.Tensor]:
    """Run the model over every item in a split and return (logits, labels)."""
    logits_list: list[torch.Tensor] = []
    labels_list: list[float] = []

    with torch.no_grad():
        for i, item in enumerate(split):
            if (i + 1) % 100 == 0:
                print(f"    {i + 1}/{len(split)}")

            try:
                events = load_events(item["path"])
                _, logits = model(events)
                if logits is None:
                    continue
                logits_list.append(logits.squeeze())
                labels_list.append(float(item["label"]))
            except Exception:
                continue

    if not logits_list:
        return torch.empty(0), torch.empty(0)

    return torch.stack(logits_list), torch.tensor(labels_list)


def format_report(name: str, metrics: dict) -> str:
    """Pretty-print one split's metrics."""
    auc = f"{metrics['roc_auc']:.4f}" if metrics["roc_auc"] is not None else "n/a"
    cm = metrics["confusion_matrix"]

    return f"""
{name.upper():<12} (threshold={metrics['threshold']:.2f})
  n_samples   = {metrics['n_samples']}  (clean {metrics['n_clean']}, malicious {metrics['n_malicious']})
  Accuracy    = {metrics['accuracy']:.2%}
  Precision   = {metrics['precision']:.2%}
  Recall      = {metrics['recall']:.2%}
  Specificity = {metrics['specificity']:.2%}
  F1 Score    = {metrics['f1']:.2%}
  ROC-AUC     = {auc}
  Confusion   = TP {cm['tp']:>4}   FN {cm['fn']:>4}
                FP {cm['fp']:>4}   TN {cm['tn']:>4}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    MODEL_PATH = "models/scbf_hybrid_v2.pt"
    SPLIT_PATH = "models/checkpoints/split_info.json"
    RESULTS_PATH = "models/evaluation_results.json"
    NUM_NODES = 50000
    THRESHOLD = 0.35        # matches the trained model's tuned threshold

    if not os.path.exists(MODEL_PATH):
        print(f"❌ Model not found: {MODEL_PATH}")
        print("   Train first: make train")
        sys.exit(1)

    if not os.path.exists(SPLIT_PATH):
        print(f"❌ Split info not found: {SPLIT_PATH}")
        print("   Train first: make train")
        sys.exit(1)

    print("=" * 78)
    print("SCBF Evaluation — train / val / test splits")
    print("=" * 78)
    print(f"Model     : {MODEL_PATH}")
    print(f"Split     : {SPLIT_PATH}")
    print(f"Threshold : {THRESHOLD}")

    # Load split
    with open(SPLIT_PATH, "r") as f:
        split_info = json.load(f)

    for k in ("train", "val", "test"):
        print(f"  {k:5} = {len(split_info[k])} samples")

    # Load model
    print("\nLoading model...")
    model = HybridClassifierV2(num_nodes=NUM_NODES)
    model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"))
    model.eval()

    # Score each split
    all_metrics: dict[str, dict] = {}
    for split_name in ("train", "val", "test"):
        print(f"\nScoring {split_name} set ({len(split_info[split_name])} samples)...")
        logits, labels = score_split(model, split_info[split_name])
        if logits.numel() == 0:
            print(f"  WARNING: {split_name} split produced no valid samples")
            continue
        all_metrics[split_name] = compute_metrics(logits, labels, threshold=THRESHOLD)

    # Report
    print("\n" + "=" * 78)
    print("RESULTS")
    print("=" * 78)
    for split_name in ("train", "val", "test"):
        if split_name in all_metrics:
            print(format_report(split_name, all_metrics[split_name]))

    # Sanity note on generalisation gap
    if "train" in all_metrics and "test" in all_metrics:
        gap = all_metrics["train"]["f1"] - all_metrics["test"]["f1"]
        print("─" * 78)
        print(f"Generalisation gap (train F1 - test F1) = {gap:+.2%}")
        if abs(gap) < 0.05:
            print("  ✓ Low gap — model is not overfitting.")
        elif abs(gap) < 0.10:
            print("  ~ Moderate gap — mild overfitting; still usable.")
        else:
            print("  ⚠ Large gap — consider more regularisation or more data.")
        print("─" * 78)

    # Persist
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": MODEL_PATH,
        "split_source": SPLIT_PATH,
        "threshold": THRESHOLD,
        "splits": all_metrics,
    }
    with open(RESULTS_PATH, "w") as f:
        json.dump(payload, f, indent=2, default=float)

    print(f"\n✓ Saved: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
