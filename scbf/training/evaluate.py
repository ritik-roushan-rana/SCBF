"""
Evaluate the trained model on train / val / test and emit the report table.

Reads the split written by train.py, so the numbers are always over the
exact same held-out sets, and the threshold tuned on val.

Outputs:
    models/evaluation_results.json
    a table on stdout in the reporting format
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import torch

from scbf.training.train import HybridClassifier, load_events, metrics, run_split


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", type=Path, default=Path("data/traces"))
    ap.add_argument("--models", type=Path, default=Path("models"))
    args = ap.parse_args()

    model_path = args.models / "scbf_hybrid.pt"
    split_path = args.models / "split_info.json"
    thr_path = args.models / "threshold.json"

    for p in (model_path, split_path):
        if not p.exists():
            raise SystemExit(f"Missing {p} — run `make train` first.")

    split = json.loads(split_path.read_text())
    thr = json.loads(thr_path.read_text())["threshold"] if thr_path.exists() else 0.5

    model = HybridClassifier()
    model.load_state_dict(torch.load(model_path, map_location="cpu"))
    model.eval()

    print("=" * 96)
    print("SCBF EVALUATION")
    print("=" * 96)
    print(f"Model     : {model_path}")
    print(f"Threshold : {thr:.2f}  (tuned on val only)\n")
    print(f"{'Split':<7}{'Samples':>9}{'Accuracy':>11}{'Precision':>12}"
          f"{'Recall':>10}{'F1':>10}{'ROC-AUC':>10}   Confusion")
    print("-" * 96)

    results = {}
    for name in ("train", "val", "test"):
        logits, labels, _ = run_split(model, split[name])
        if logits.numel() == 0:
            print(f"{name:<7}  no scorable samples")
            continue
        m = metrics(logits, labels, thr)
        results[name] = m
        auc = f"{m['roc_auc']:.4f}" if m["roc_auc"] is not None else "n/a"
        print(f"{name.capitalize():<7}{m['n']:>9}{m['accuracy']:>10.2%}"
              f"{m['precision']:>11.2%}{m['recall']:>9.2%}{m['f1']:>9.2%}{auc:>10}"
              f"   TP {m['tp']:<4} FN {m['fn']:<4} FP {m['fp']:<4} TN {m['tn']:<4}")

    if "train" in results and "test" in results:
        gap = results["train"]["f1"] - results["test"]["f1"]
        print(f"\nGeneralisation gap (train F1 - test F1) = {gap:+.2%}")
        if abs(gap) > 0.10:
            print("  ⚠ large gap — overfitting")

    out = args.models / "evaluation_results.json"
    with open(out, "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(),
                   "model": str(model_path), "threshold": thr,
                   "splits": results}, f, indent=2, default=float)
    print(f"\nSaved: {out}")
    print("\nReminder: these numbers mean nothing unless `make audit` passes.")


if __name__ == "__main__":
    main()
