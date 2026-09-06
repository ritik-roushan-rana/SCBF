"""
Full rate-normalized ablation of Hybrid V2's 45-feature set.

Earlier tests showed:
  - Trace length (n_events) ALONE:      ROC-AUC 0.8549
  - A 10-feature rate-based subset:     ROC-AUC 0.8257
  - Original TGN embedding (all epochs): ROC-AUC ~0.65-0.72

This script converts Hybrid V2's FULL 45-feature set to rate-based/
length-independent form (dropping raw magnitude features like n_events,
n_exec, n_open, n_unique_files, etc. entirely, keeping only fractions,
ratios, and log-scaled time features that don't trivially encode trace
length), then trains and evaluates using the SAME methodology as Hybrid V2
(threshold tuned on val, reported on test) for a direct, fair comparison
against the reported 95.54% accuracy / 92.31% F1.

If this gets close to those numbers -> real behavioral signal, length
wasn't doing the heavy lifting after all.

If this drops sharply (towards the ~55-67% accuracy / 0.82-0.85 AUC range
seen in the smaller confound tests) -> confirms Hybrid V2's headline
number is substantially inflated by the trace-length confound.

Usage:
    python ablation_rate_normalized.py
"""

import json
import os
import re
import numpy as np
from collections import Counter


def load_events(path):
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]


def extract_features_v2_rate(events):
    """
    Rate-normalized version of Hybrid V2's 45 features.

    Design: every feature that was a raw COUNT in the original (which
    necessarily correlates with trace length) is divided by n_events (or by
    n_paths/n_comms where more appropriate), so the feature reflects a
    PROPORTION of activity rather than an absolute volume. Features that
    were already ratios/fractions/diversity-normalized in the original are
    kept as-is. Raw magnitude features with no natural normalization
    (max_path_depth, avg_path_length) are kept, since path depth/length
    don't scale with trace length the way event counts do.

    n_events itself, and all raw absolute counts, are DELIBERATELY EXCLUDED
    -- that's the entire point of this ablation.
    """
    if not events:
        return np.zeros(38, dtype=np.float32)

    n_events = len(events)
    event_types = Counter(e.get('type', '') for e in events)
    paths = [e.get('fname', '') for e in events if e.get('fname')]
    n_paths = max(1, len(paths))
    comms = [e.get('comm', '') for e in events]
    n_comms = max(1, len(comms))

    unique_pids = set(e.get('pid', 0) for e in events)
    unique_comms = set(comms)
    unique_files = set(paths)

    features = []

    # Event type ratios (already length-independent in original design)
    features.append(event_types.get('exec', 0) / max(1, n_events))
    features.append(event_types.get('open', 0) / max(1, n_events))
    features.append(event_types.get('connect', 0) / max(1, n_events))
    features.append(len(event_types))  # type diversity: bounded 1-3, not length-scaled

    # Diversity ratios (already length-independent in original design)
    features.append(len(unique_pids) / max(1, n_events))
    features.append(len(unique_comms) / max(1, n_events))
    features.append(len(unique_files) / max(1, n_events))

    # Path category features -- converted from raw counts to PROPORTION of paths
    features.append(sum(1 for p in paths if '/tmp/' in p or '/var/tmp/' in p) / n_paths)
    features.append(sum(1 for p in paths if '/.' in p) / n_paths)
    features.append(sum(1 for p in paths if p.startswith('/usr/') or p.startswith('/etc/')) / n_paths)
    features.append(sum(1 for p in paths if '/home/' in p or p.startswith('~')) / n_paths)
    features.append(sum(1 for p in paths if p.startswith('/root/')) / n_paths)
    features.append(sum(1 for p in paths if p.startswith('/proc/')) / n_paths)
    features.append(sum(1 for p in paths if p.startswith('/dev/')) / n_paths)
    features.append(sum(1 for p in paths if '/bin/' in p or '/sbin/' in p) / n_paths)
    features.append(sum(1 for p in paths if '/lib/' in p) / n_paths)
    features.append(sum(1 for p in paths if 'site-packages' in p or '.py' in p) / n_paths)
    features.append(sum(1 for p in paths if 'ssh' in p.lower() or '.ssh/' in p) / n_paths)

    # Network activity ratios
    n_connects = event_types.get('connect', 0)
    features.append(int(n_connects > 0))  # binary flag, not magnitude
    features.append(n_connects / max(1, n_events))

    # Suspicious command PROPORTIONS (converted from raw counts)
    features.append(sum(1 for c in comms if 'curl' in c.lower() or 'wget' in c.lower()) / n_comms)
    features.append(sum(1 for c in comms if c.lower() in ['nc', 'ncat', 'netcat']) / n_comms)
    features.append(sum(1 for c in comms if c.lower() in ['bash', 'sh', 'zsh', 'ksh']) / n_comms)
    features.append(sum(1 for c in comms if 'python' in c.lower()) / n_comms)
    features.append(sum(1 for c in comms if c.lower() in ['node', 'ruby', 'perl']) / n_comms)
    features.append(sum(1 for c in comms if c.lower() in ['chmod', 'chown']) / n_comms)
    features.append(sum(1 for c in comms if c.lower() in ['ssh', 'scp', 'sftp']) / n_comms)
    features.append(sum(1 for c in comms if c.lower() in ['base64', 'openssl']) / n_comms)

    # Time-based features: kept as-is. These reflect PACING (how fast events
    # happen), not volume, so they are not the same confound as raw counts.
    timestamps = [e.get('ts', 0) for e in events if e.get('ts')]
    if len(timestamps) > 1:
        timestamps_sorted = sorted(timestamps)
        duration = timestamps_sorted[-1] - timestamps_sorted[0]
        events_per_sec = n_events / max(1, duration / 1e9)
        gaps = [timestamps_sorted[i + 1] - timestamps_sorted[i] for i in range(len(timestamps_sorted) - 1)]
        avg_gap = np.mean(gaps) if gaps else 0
        max_gap = max(gaps) if gaps else 0
        min_gap = min(gaps) if gaps else 0
    else:
        duration = 0
        events_per_sec = 0
        avg_gap = 0
        max_gap = 0
        min_gap = 0
    features.append(np.log1p(avg_gap))
    features.append(np.log1p(max_gap))
    features.append(np.log1p(min_gap))
    features.append(np.log1p(events_per_sec))
    # NOTE: log1p(duration) intentionally excluded -- wall-clock duration
    # can itself be a length-like confound (short-running install = short
    # duration), same concern as n_events.

    # Path pattern proportions
    features.append(sum(1 for p in paths if re.search(r'[A-Za-z0-9+/=]{40,}', p)) / n_paths)
    features.append(sum(1 for p in paths if 'http' in p.lower() or '://' in p) / n_paths)

    # Path structure features -- kept as-is (not count-based, reflect
    # structure of paths touched, not how MANY were touched)
    features.append(max((p.count('/') for p in paths), default=0))
    features.append(np.mean([len(p) for p in paths]) if paths else 0)
    features.append(len(set('/'.join(p.split('/')[:-1]) for p in paths)) / n_paths)

    return np.array(features, dtype=np.float32)


def build_matrix(data_list):
    X, y = [], []
    for item in data_list:
        try:
            events = load_events(item['path'])
            feats = extract_features_v2_rate(events)
            X.append(feats)
            y.append(item['label'])
        except Exception as e:
            print(f"  WARNING: failed on {item['path']}: {e}")
            continue
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


def main():
    CHECKPOINT_DIR = "models/checkpoints"
    split_path = os.path.join(CHECKPOINT_DIR, "split_info.json")
    if not os.path.exists(split_path):
        print(f"ERROR: {split_path} not found. Run train_with_split.py first.")
        return

    with open(split_path, 'r') as f:
        split_info = json.load(f)

    print("Building LENGTH-INDEPENDENT feature matrices (same split as Hybrid V2)...")
    X_train, y_train = build_matrix(split_info['train'])
    X_val, y_val = build_matrix(split_info['val'])
    X_test, y_test = build_matrix(split_info['test'])
    print(f"  Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")

    mean = X_train.mean(axis=0, keepdims=True)
    std = X_train.std(axis=0, keepdims=True) + 1e-6
    X_train_n = (X_train - mean) / std
    X_val_n = (X_val - mean) / std
    X_test_n = (X_test - mean) / std

    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, confusion_matrix
    )

    print("\nTraining logistic regression on LENGTH-INDEPENDENT features...")
    clf = LogisticRegression(max_iter=2000, class_weight='balanced', C=1.0)
    clf.fit(X_train_n, y_train)

    # Threshold search on val, exactly like Hybrid V2's methodology
    val_probs = clf.predict_proba(X_val_n)[:, 1]
    best_thresh, best_f1 = 0.5, 0.0
    for t in np.arange(0.05, 0.95, 0.02):
        preds = (val_probs > t).astype(int)
        f1 = f1_score(y_val, preds, zero_division=0)
        if f1 > best_f1:
            best_f1, best_thresh = f1, t
    print(f"Best validation threshold: {best_thresh:.2f} (F1={best_f1:.2%})")

    test_probs = clf.predict_proba(X_test_n)[:, 1]
    test_preds = (test_probs > best_thresh).astype(int)

    acc = accuracy_score(y_test, test_preds)
    prec = precision_score(y_test, test_preds, zero_division=0)
    rec = recall_score(y_test, test_preds, zero_division=0)
    f1 = f1_score(y_test, test_preds, zero_division=0)
    auc = roc_auc_score(y_test, test_probs)
    cm = confusion_matrix(y_test, test_preds)

    print("\n" + "=" * 80)
    print(f"LENGTH-INDEPENDENT BASELINE (threshold={best_thresh:.2f})")
    print("=" * 80)
    print(f"Accuracy:  {acc:.2%}   (Hybrid V2 reported: 95.54%)")
    print(f"Precision: {prec:.2%}   (Hybrid V2 reported: 91.53%)")
    print(f"Recall:    {rec:.2%}   (Hybrid V2 reported: 93.10%)")
    print(f"F1 Score:  {f1:.2%}   (Hybrid V2 reported: 92.31%)")
    print(f"ROC-AUC:   {auc:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"                Predicted")
    print(f"              Clean  Malicious")
    print(f"Actual Clean    {cm[0][0]:3d}  {cm[0][1]:3d}")
    print(f"Actual Mal      {cm[1][0]:3d}  {cm[1][1]:3d}")
    print("=" * 80)

    coefs = clf.coef_[0]
    top_idx = np.argsort(np.abs(coefs))[::-1][:10]
    print("\nTop 10 most influential LENGTH-INDEPENDENT features:")
    for i in top_idx:
        print(f"  feature[{i:2d}]  coef={coefs[i]:+.4f}")

    gap = 0.9231 - f1  # Hybrid V2's reported F1 minus this result
    print(f"""
Interpretation:
  F1 gap vs Hybrid V2's reported 92.31%: {gap:+.2%}

  - Small gap (<10 points) -> the real behavioral signal in the rate-based
    features explains most of Hybrid V2's performance; trace length was a
    minor contributor.
  - Large gap (>20 points, i.e. this lands closer to the 55-67% range seen
    in the earlier n_events / 10-feature confound tests) -> confirms that
    Hybrid V2's headline 92% F1 is substantially inflated by the trace-
    length confound, not genuine malicious-behavior detection. In that case
    I would NOT recommend calling it production-ready or pushing it as the
    final result without addressing the length confound directly (e.g. by
    truncating/normalizing traces to a fixed length before feature
    extraction, or by investigating and fixing whatever collection process
    causes malicious traces to be systematically shorter).
""")


if __name__ == "__main__":
    main()
