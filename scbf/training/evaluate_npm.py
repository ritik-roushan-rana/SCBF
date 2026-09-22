"""
Evaluate one or more trained NPM hybrid models on the saved train/val/test
split (models/checkpoints_npm/split_info.json).

With several models, their logits are averaged (a seed ensemble); the
decision threshold is re-tuned on the validation split and the test split
is scored once with that threshold.

Usage:
    python -m scbf.training.evaluate_npm                       # models/scbf_npm_hybrid_v1.pt
    python -m scbf.training.evaluate_npm models/scbf_npm_hybrid_v1.pt \
        models/checkpoints_npm/scbf_npm_hybrid_v1_seed1.pt ...
    python -m scbf.training.evaluate_npm ... --save models/scbf_npm_hybrid_v1_ensemble.pt
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.multiprocessing as mp

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from scbf.training.train_npm_hybrid import (  # noqa: E402
    MODEL_OUTPUT, SPLIT_FILE, cache_file,
    NPMHybridClassifier, compute_metrics, fmt, run_eval, _worker_init,
)


def load_model(path):
    state = torch.load(path, map_location="cpu", weights_only=False)
    if "model_state_dict" in state:
        state = state["model_state_dict"]
    # stat_dim (base vs rich feature set) is recorded by the normaliser buffer
    model = NPMHybridClassifier(stat_dim=state["feat_mean"].numel())
    model.load_state_dict(state)
    model.eval()
    return model


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("models", nargs="*", default=[str(MODEL_OUTPUT)])
    ap.add_argument("--workers", type=int, default=max(1, min(12, (os.cpu_count() or 2) - 2)))
    ap.add_argument("--save", default=None, help="save the ensemble as a single checkpoint")
    ap.add_argument("--results", default=str(PROJECT_ROOT / "models" / "npm_evaluation_results.json"))
    ap.add_argument("--split", default=str(SPLIT_FILE), help="split_info.json to evaluate on")
    ap.add_argument("--exclude-inert", action="store_true",
                    help="also report metrics with install-inert malware removed from val/test")
    args = ap.parse_args()

    split = json.load(open(args.split))
    inert = set()
    if args.exclude_inert:
        from scbf.training.train_npm_hybrid import INERT_FILE
        inert = set(json.load(open(INERT_FILE))["malware"]["inert"])
    models = [load_model(m) for m in args.models]
    dims = {m.feat_mean.numel() for m in models}
    if len(dims) != 1:
        raise SystemExit(f"models use different feature sets (stat_dim={sorted(dims)}); cannot ensemble")
    stat_dim = dims.pop()
    rich = models[0].uses_rich_features
    cache = torch.load(cache_file(rich), map_location="cpu", weights_only=False)
    by_path = {k.split("|")[0]: v for k, v in cache.items() if k != "_meta"}

    items, idx = [], {}
    for name in ("train", "val", "test"):
        idx[name] = []
        for rel, label in split[name]:
            p = str(PROJECT_ROOT / rel)
            if p not in by_path:
                continue
            idx[name].append(len(items))
            items.append((by_path[p], label, os.path.basename(p) in inert and label == 1))
    samples = [s for s, _, _ in items]
    labels = [l for _, l, _ in items]
    is_inert = [i for _, _, i in items]

    print(f"Models: {len(models)}   feature set: {'rich' if rich else 'base'} ({stat_dim} dims)")
    for m in args.models:
        print(f"  {m}")

    pool = None
    if args.workers > 1:
        pool = mp.get_context("spawn").Pool(
            args.workers, initializer=_worker_init,
            initargs=(samples, labels, 50000, stat_dim, 1.0, 2.0),
        )
    try:
        logits = {}
        for name in ("val", "test"):
            acc = None
            for model in models:
                lg, kept = run_eval(pool, model, idx[name], args.workers)
                acc = lg if acc is None else acc + lg
            keep = [k for k, i in enumerate(kept) if not is_inert[i]]
            logits[name] = ((acc / len(models))[keep], torch.tensor([float(labels[kept[k]]) for k in keep]))
            if len(keep) != len(kept):
                print(f"  {name}: dropped {len(kept) - len(keep)} install-inert malware traces")
    finally:
        if pool is not None:
            pool.close()
            pool.join()

    val_logits, val_labels = logits["val"]
    best_thr, best_f1 = 0.5, -1.0
    for thr in np.arange(0.05, 0.96, 0.01):
        f1 = compute_metrics(val_logits, val_labels, float(thr))["f1"]
        if f1 > best_f1 + 1e-9:
            best_thr, best_f1 = float(thr), f1
    vm = compute_metrics(val_logits, val_labels, best_thr)
    test_logits, test_labels = logits["test"]
    tm = compute_metrics(test_logits, test_labels, best_thr)
    tm_05 = compute_metrics(test_logits, test_labels, 0.5)

    print(f"\nValidation threshold: {best_thr:.2f}")
    print(f"Validation : {fmt(vm)}")
    print("\nFINAL NPM TEST RESULTS" + (" (ensemble)" if len(models) > 1 else ""))
    print("-" * 50)
    print(f"Accuracy  : {tm['accuracy']:.2%}")
    print(f"Precision : {tm['precision']:.2%}")
    print(f"Recall    : {tm['recall']:.2%}")
    print(f"F1 Score  : {tm['f1']:.2%}")
    print(f"FPR       : {tm['fpr']:.2%}")
    print(f"ROC-AUC   : {tm['auc']:.4f}")
    print(f"(at 0.50) : {fmt(tm_05)}")
    print("\nConfusion Matrix")
    print("              Clean  Malicious")
    print(f"Actual Clean  {tm['tn']:5d}  {tm['fp']:5d}")
    print(f"Actual Mal    {tm['fn']:5d}  {tm['tp']:5d}")

    if args.save:
        torch.save({
            "ensemble": [m.state_dict() for m in models],
            "threshold": best_thr,
            "feature_dim": stat_dim,
            "rich": rich,
        }, args.save)
        print(f"\nEnsemble saved -> {args.save}")

    with open(args.results, "w") as f:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dataset": "RQ1_NPM",
            "models": args.models,
            "threshold": best_thr,
            "validation": vm,
            "test": tm,
            "test_at_0.5": tm_05,
        }, f, indent=2)
    print(f"Results saved  -> {args.results}")


if __name__ == "__main__":
    main()
