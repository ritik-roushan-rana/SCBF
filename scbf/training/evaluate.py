"""
Evaluation script for SCBF model.

Evaluates trained model on test set with detailed metrics:
- Accuracy, Precision, Recall, F1
- ROC-AUC curve
- Distance distributions
- Confusion matrix

FIXES (v2):
1. save_results' convert() helper is now recursive. Previously it only
   unwrapped one level of nesting, so results['split']['metrics']['threshold']
   (three levels deep) was never converted from np.float32 to a native
   Python float, causing `TypeError: Object of type float32 is not JSON
   serializable`.
2. Embeddings are now L2-normalized before computing distances, to stay
   consistent with the normalized training script (train_with_split.py v2).
   If the model is trained in normalized (unit-sphere) space but evaluated
   with raw, unnormalized distances, the reported metrics don't reflect what
   the model was actually optimized for.
"""

import torch
import json
import numpy as np
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.tgn_encoder import TGNEncoder
from models.itbg_constructor import ITBGConstructor


def load_events(path):
    """Load events from JSONL file."""
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]


def load_split_info(checkpoint_dir="models/checkpoints"):
    """Load train/val/test split information."""
    split_path = os.path.join(checkpoint_dir, "split_info.json")

    if not os.path.exists(split_path):
        print(f"ERROR: Split info not found at {split_path}")
        print("Please run train_with_split.py first to generate splits.")
        return None

    with open(split_path, 'r') as f:
        return json.load(f)


def _l2_normalize(arr, axis=-1, eps=1e-8):
    """L2-normalize a numpy array along the given axis."""
    norm = np.sqrt((arr ** 2).sum(axis=axis, keepdims=True))
    return arr / np.maximum(norm, eps)


def compute_embeddings_and_distances(model, data_list, clean_centroid=None, normalize=True):
    """
    Compute embeddings and distances to clean centroid.

    Args:
        model: TGNEncoder model
        data_list: List of {'path': ..., 'label': ...} dicts
        clean_centroid: Pre-computed clean centroid (optional)
        normalize: If True (default), L2-normalize embeddings before
            computing distances. This MUST match whatever the model was
            trained with -- the fixed train_with_split.py normalizes by
            default, so this defaults to True here as well.

    Returns:
        embeddings: numpy array of shape (N, embedding_dim)
        distances: numpy array of shape (N,) - L2 distances to clean centroid
        labels: numpy array of shape (N,)
        centroid: clean centroid array
    """
    embeddings_list = []
    labels_list = []

    for item in data_list:
        path = item['path']
        label = item['label']

        model.memory_bank.reset_memory()
        constructor = ITBGConstructor(model)

        try:
            events = load_events(path)
            dna = constructor.replay_session(events)

            if dna is not None:
                embeddings_list.append(dna.detach().cpu().numpy())
                labels_list.append(label)
        except Exception as e:
            print(f"  WARNING: Failed to process {path}: {e}")
            continue

    if len(embeddings_list) == 0:
        return None, None, None, None

    embeddings = np.array(embeddings_list)
    labels = np.array(labels_list)

    if normalize:
        embeddings = _l2_normalize(embeddings, axis=-1)

    # Compute clean centroid if not provided
    if clean_centroid is None:
        clean_mask = labels == 0
        if clean_mask.sum() > 0:
            clean_centroid = embeddings[clean_mask].mean(axis=0)
        else:
            clean_centroid = embeddings.mean(axis=0)
        if normalize:
            clean_centroid = _l2_normalize(clean_centroid, axis=-1)
    else:
        if isinstance(clean_centroid, torch.Tensor):
            clean_centroid = clean_centroid.cpu().numpy()
        if normalize:
            clean_centroid = _l2_normalize(clean_centroid, axis=-1)

    # Compute L2 distances to clean centroid
    distances = np.sqrt(((embeddings - clean_centroid) ** 2).sum(axis=1))

    return embeddings, distances, labels, clean_centroid


def compute_metrics(distances, labels, threshold=None):
    """
    Compute classification metrics.

    If threshold is None, uses the mean distance of clean samples + 2*std

    Args:
        distances: numpy array of distances
        labels: numpy array of true labels (0=clean, 1=malicious)
        threshold: distance threshold for classification

    Returns:
        metrics: dict with accuracy, precision, recall, f1, etc.
    """
    if threshold is None:
        # Auto-compute threshold from clean samples
        clean_distances = distances[labels == 0]
        if len(clean_distances) > 0:
            threshold = clean_distances.mean() + 2 * clean_distances.std()
        else:
            threshold = distances.mean()

    # Predict: distance > threshold => malicious
    predictions = (distances > threshold).astype(int)

    # Compute confusion matrix
    tp = ((predictions == 1) & (labels == 1)).sum()
    tn = ((predictions == 0) & (labels == 0)).sum()
    fp = ((predictions == 1) & (labels == 0)).sum()
    fn = ((predictions == 0) & (labels == 1)).sum()

    # Compute metrics
    accuracy = (tp + tn) / len(labels) if len(labels) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # False positive rate
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        'threshold': threshold,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'fpr': fpr,
        'tp': int(tp),
        'tn': int(tn),
        'fp': int(fp),
        'fn': int(fn)
    }


def compute_auc(distances, labels):
    """
    Compute ROC-AUC score.

    Args:
        distances: numpy array of distances (higher = more likely malicious)
        labels: numpy array of true labels (0=clean, 1=malicious)

    Returns:
        auc: ROC-AUC score
    """
    try:
        from sklearn.metrics import roc_auc_score
        auc = roc_auc_score(labels, distances)
        return auc
    except ImportError:
        print("  WARNING: sklearn not available, skipping AUC computation")
        return None
    except ValueError as e:
        print(f"  WARNING: Could not compute AUC: {e}")
        return None


def print_metrics(split_name, metrics, distances, labels):
    """Pretty print evaluation metrics."""
    print(f"\n{'=' * 80}")
    print(f"{split_name.upper()} SET RESULTS")
    print(f"{'=' * 80}")

    print(f"\nDataset:")
    print(f"  Total samples: {len(labels)}")
    print(f"  Clean: {(labels == 0).sum()}")
    print(f"  Malicious: {(labels == 1).sum()}")

    print(f"\nDistance Statistics:")
    clean_dists = distances[labels == 0]
    mal_dists = distances[labels == 1]

    if len(clean_dists) > 0:
        print(f"  Clean distances: mean={clean_dists.mean():.4f}, "
              f"std={clean_dists.std():.4f}, "
              f"min={clean_dists.min():.4f}, "
              f"max={clean_dists.max():.4f}")

    if len(mal_dists) > 0:
        print(f"  Malicious distances: mean={mal_dists.mean():.4f}, "
              f"std={mal_dists.std():.4f}, "
              f"min={mal_dists.min():.4f}, "
              f"max={mal_dists.max():.4f}")

    # Separation ratio: how far malicious sits relative to how tight the
    # clean cluster is. This is a clearer separability signal than either
    # raw distance alone -- watch this number across model versions.
    if len(clean_dists) > 0 and len(mal_dists) > 0 and clean_dists.mean() > 0:
        ratio = mal_dists.mean() / clean_dists.mean()
        print(f"  Separation Ratio (mal_mean / clean_mean): {ratio:.4f}")

    print(f"\nClassification (threshold={metrics['threshold']:.4f}):")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    print(f"  FPR:       {metrics['fpr']:.4f}")

    print(f"\nConfusion Matrix:")
    print(f"                  Predicted")
    print(f"                Clean  Malicious")
    print(f"  Actual Clean    {metrics['tn']:4d}  {metrics['fp']:4d}")
    print(f"  Actual Mal      {metrics['fn']:4d}  {metrics['tp']:4d}")

    # Compute AUC
    auc = compute_auc(distances, labels)
    if auc is not None:
        print(f"\nROC-AUC: {auc:.4f}")


def _convert(obj):
    """
    Recursively convert numpy/torch scalar types to native Python types so
    the result is JSON serializable. FIX: this replaces the old one-level
    `convert()` helper, which didn't recurse into nested dicts -- that's why
    results['split']['metrics']['threshold'] (3 levels deep) crashed
    json.dump with `TypeError: Object of type float32 is not JSON
    serializable`.
    """
    if isinstance(obj, dict):
        return {k: _convert(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_convert(v) for v in obj]
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, torch.Tensor):
        return obj.detach().cpu().tolist()
    # Catch any other numpy/torch scalar-like objects with a .item() method
    if hasattr(obj, 'item') and not isinstance(obj, (str, bytes)):
        try:
            return obj.item()
        except (ValueError, TypeError):
            pass
    return obj


def save_results(results, output_path="models/checkpoints/evaluation_results.json"):
    """Save evaluation results to JSON."""
    results_serializable = _convert(results)

    with open(output_path, 'w') as f:
        json.dump(results_serializable, f, indent=2)

    print(f"\nResults saved to: {output_path}")


def main():
    """Main evaluation function."""

    # Configuration
    MODEL_PATH = "models/tgn_v2_best.pt"
    CHECKPOINT_DIR = "models/checkpoints"
    NUM_NODES = 50000
    NORMALIZE = True  # Must match how the model was trained.

    # Check if model exists
    if not os.path.exists(MODEL_PATH):
        print(f"ERROR: Model not found at {MODEL_PATH}")
        print("Please train the model first using train_with_split.py")
        return

    # Load split info
    print("Loading split information...")
    split_info = load_split_info(CHECKPOINT_DIR)

    if split_info is None:
        return

    print(f"Loaded splits:")
    print(f"  Train: {split_info['train_size']} samples")
    print(f"  Val: {split_info['val_size']} samples")
    print(f"  Test: {split_info['test_size']} samples")

    # Load model
    print(f"\nLoading model from {MODEL_PATH}...")
    model = TGNEncoder(num_nodes=NUM_NODES)
    model.load_state_dict(torch.load(MODEL_PATH))
    model.eval()

    # Evaluate on each split
    results = {}
    clean_centroid = None  # Computed fresh on train set, reused for val/test

    for split_name in ['train', 'val', 'test']:
        print(f"\n{'=' * 80}")
        print(f"Evaluating on {split_name} set...")
        print(f"{'=' * 80}")

        data_list = split_info[split_name]

        with torch.no_grad():
            embeddings, distances, labels, centroid = compute_embeddings_and_distances(
                model, data_list,
                clean_centroid=clean_centroid if split_name != 'train' else None,
                normalize=NORMALIZE
            )

        if distances is None:
            print(f"WARNING: No valid samples in {split_name} set")
            continue

        # Reuse the train-set clean centroid for val/test evaluation, so all
        # splits are measured against the same reference point.
        if split_name == 'train':
            clean_centroid = centroid

        # Compute metrics
        metrics = compute_metrics(distances, labels)

        # Print results
        print_metrics(split_name, metrics, distances, labels)

        # Store results
        results[split_name] = {
            'metrics': metrics,
            'n_samples': len(labels),
            'n_clean': int((labels == 0).sum()),
            'n_malicious': int((labels == 1).sum()),
            'auc': compute_auc(distances, labels)
        }

    # Save results
    save_results(results, os.path.join(CHECKPOINT_DIR, "evaluation_results.json"))

    print("\n" + "=" * 80)
    print("EVALUATION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()