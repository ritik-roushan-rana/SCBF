"""
Strip sandbox-bootstrap noise and re-test for genuine behavioral signal.

inspect_samples.py revealed that home_ratio/hidden_ratio (top features in
the "length-independent" ablation) are actually dominated by:

  - pyenv's own stdlib files living under /home/<user>/.pyenv/...
    (counted as both "home" and "hidden" due to naive substring matching)
  - sudo/PAM bootstrap checks (/etc/passwd, /etc/login.defs, /etc/group,
    /run/systemd/userdb/, pam.d, pam_*.so)
  - pip's own temp scaffolding (/tmp/pip-install-*, /tmp/pip-ephem-wheel-cache-*)
  - terminal/tty plumbing (/dev/pts, /dev/tty, /dev/ptmx, /dev/null)

These are roughly CONSTANT per trace regardless of what the package does,
so any "rate" feature (constant / n_events) is really just an inverted
proxy for trace length -- not real malicious behavior.

This script excludes all of that bootstrap noise, keeping only paths/comms
that reflect the PACKAGE's own induced activity, and re-runs the same
rate-normalized logistic regression to see if any real signal survives.

Usage:
    python check_bootstrap_stripped.py
"""

import json
import os
import re
import numpy as np
from collections import Counter


BOOTSTRAP_PATH_PATTERNS = [
    re.compile(r'\.pyenv/'),                      # pyenv's own stdlib files
    re.compile(r'^/etc/(passwd|login\.defs|group|shadow|nsswitch\.conf)$'),
    re.compile(r'^/etc/pam\.d/'),
    re.compile(r'^/etc/security/'),
    re.compile(r'pam_.*\.so'),
    re.compile(r'^/run/systemd/userdb/'),
    re.compile(r'^/etc/ld\.so\.cache$'),
    re.compile(r'^/dev/(pts|tty|ptmx|null)'),
    re.compile(r'^/tmp/pip-(install|ephem-wheel-cache|req-build)-'),
]


def load_events(path):
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]


def is_bootstrap_path(p):
    return any(pat.search(p) for pat in BOOTSTRAP_PATH_PATTERNS)


def extract_stripped_features(events):
    """Same style of rate features as before, but computed only over
    non-bootstrap events -- i.e. activity actually attributable to the
    package itself, not the sandbox/interpreter/sudo plumbing."""
    real_events = [
        e for e in events
        if not (e.get('fname') and is_bootstrap_path(e['fname']))
        and e.get('comm', '') != 'sudo'
    ]
    n_real = len(real_events)
    if n_real == 0:
        return None, 0

    event_types = Counter(e.get('type', '') for e in real_events)
    paths = [e.get('fname', '') for e in real_events if e.get('fname')]
    n_paths = max(1, len(paths))
    comms = [e.get('comm', '') for e in real_events]
    n_comms = max(1, len(comms))
    unique_files = set(paths)

    features = []
    features.append(event_types.get('exec', 0) / max(1, n_real))
    features.append(event_types.get('open', 0) / max(1, n_real))
    features.append(event_types.get('connect', 0) / max(1, n_real))
    features.append(len(unique_files) / n_paths)
    features.append(sum(1 for p in paths if '/tmp/' in p) / n_paths)
    features.append(sum(1 for p in paths if '/home/' in p) / n_paths)  # real home access
    features.append(sum(1 for p in paths if '/root/' in p) / n_paths)
    features.append(sum(1 for p in paths if 'site-packages' in p) / n_paths)
    features.append(sum(1 for p in paths if 'ssh' in p.lower()) / n_paths)
    features.append(sum(1 for p in paths if '/usr/' in p or '/etc/' in p) / n_paths)  # real system
    features.append(sum(1 for c in comms if 'curl' in c.lower() or 'wget' in c.lower()) / n_comms)
    features.append(sum(1 for c in comms if c.lower() in ['bash', 'sh', 'zsh']) / n_comms)
    features.append(sum(1 for c in comms if c.lower() in ['chmod', 'chown']) / n_comms)
    features.append(sum(1 for c in comms if c.lower() in ['base64', 'openssl']) / n_comms)
    features.append(int(event_types.get('connect', 0) > 0))
    n_base64_like = sum(1 for p in paths if re.search(r'[A-Za-z0-9+/=]{40,}', p))
    features.append(n_base64_like / n_paths)

    return np.array(features, dtype=np.float32), n_real


def build_matrix(data_list):
    X, y, real_counts = [], [], []
    for item in data_list:
        try:
            events = load_events(item['path'])
            feats, n_real = extract_stripped_features(events)
            if feats is not None:
                X.append(feats)
                y.append(item['label'])
                real_counts.append(n_real)
        except Exception as e:
            print(f"  WARNING: failed on {item['path']}: {e}")
            continue
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64), np.array(real_counts)


def main():
    CHECKPOINT_DIR = "models/checkpoints"
    split_path = os.path.join(CHECKPOINT_DIR, "split_info.json")
    if not os.path.exists(split_path):
        print(f"ERROR: {split_path} not found.")
        return

    with open(split_path, 'r') as f:
        split_info = json.load(f)

    print("Building bootstrap-STRIPPED feature matrices...")
    X_train, y_train, rc_train = build_matrix(split_info['train'])
    X_val, y_val, rc_val = build_matrix(split_info['val'])
    X_test, y_test, rc_test = build_matrix(split_info['test'])
    print(f"  Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")

    # How much "real" (non-bootstrap) activity is left, per class?
    print(f"\nReal (non-bootstrap) event counts after stripping:")
    all_rc = np.concatenate([rc_train, rc_val, rc_test])
    all_y = np.concatenate([y_train, y_val, y_test])
    print(f"  Clean:     mean={all_rc[all_y==0].mean():.1f}, median={np.median(all_rc[all_y==0]):.1f}")
    print(f"  Malicious: mean={all_rc[all_y==1].mean():.1f}, median={np.median(all_rc[all_y==1]):.1f}")
    corr = np.corrcoef(all_rc.astype(float), all_y)[0, 1]
    print(f"  Correlation (real event count vs label): {corr:.4f}")

    mean = X_train.mean(axis=0, keepdims=True)
    std = X_train.std(axis=0, keepdims=True) + 1e-6
    X_train_n = (X_train - mean) / std
    X_val_n = (X_val - mean) / std
    X_test_n = (X_test - mean) / std

    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

    clf = LogisticRegression(max_iter=2000, class_weight='balanced')
    clf.fit(X_train_n, y_train)

    val_probs = clf.predict_proba(X_val_n)[:, 1]
    best_thresh, best_f1 = 0.5, 0.0
    for t in np.arange(0.05, 0.95, 0.02):
        preds = (val_probs > t).astype(int)
        f1 = f1_score(y_val, preds, zero_division=0)
        if f1 > best_f1:
            best_f1, best_thresh = f1, t

    test_probs = clf.predict_proba(X_test_n)[:, 1]
    test_preds = (test_probs > best_thresh).astype(int)

    acc = accuracy_score(y_test, test_preds)
    prec = precision_score(y_test, test_preds, zero_division=0)
    rec = recall_score(y_test, test_preds, zero_division=0)
    f1 = f1_score(y_test, test_preds, zero_division=0)
    auc = roc_auc_score(y_test, test_probs)
    cm = confusion_matrix(y_test, test_preds)

    print(f"\n{'=' * 80}")
    print(f"BOOTSTRAP-STRIPPED RESULT (threshold={best_thresh:.2f})")
    print(f"{'=' * 80}")
    print(f"Accuracy:  {acc:.2%}")
    print(f"Precision: {prec:.2%}")
    print(f"Recall:    {rec:.2%}")
    print(f"F1 Score:  {f1:.2%}")
    print(f"ROC-AUC:   {auc:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"                Predicted")
    print(f"              Clean  Malicious")
    print(f"Actual Clean    {cm[0][0]:3d}  {cm[0][1]:3d}")
    print(f"Actual Mal      {cm[1][0]:3d}  {cm[1][1]:3d}")
    print(f"""
Interpretation:
  - If "real event count" is still strongly correlated with label (printed
    above) and/or this result is still near-perfect, the confound goes
    deeper than pyenv/sudo/pip bootstrap noise -- something else about how
    malicious vs clean traces were captured still differs systematically.
  - If this result drops substantially (into a more modest, believable
    range for behavioral malware detection, e.g. 65-80% F1) compared to
    the previous 98.31% F1, that CONFIRMS the earlier number was almost
    entirely a sandbox-bootstrap artifact, not learned malicious behavior.
  - Either way, do not trust the model's real-world detection rate until
    this number stabilizes to something well below 98% and the "real event
    count vs label" correlation printed above is weak (|r| < 0.2 or so).
""")


if __name__ == "__main__":
    main()
