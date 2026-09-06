"""
Diagnostic: is the model just learning trace length?

The feature-difference table from verify_model.py shows almost every
count-based feature (n_events, open events, unique_files, tmp_paths,
python_cmd, lib_paths...) differing between classes by roughly the SAME
ratio (~0.4-0.45x), regardless of what each feature actually counts. That
pattern is the signature of a confound: if malicious traces are simply
shorter/less active overall (e.g. sandbox kills the process early, install
fails partway through), every count-based feature becomes a proxy for trace
length rather than a specific behavioral signal.

This script tests that hypothesis directly:

  1. Reports the correlation between raw trace length (n_events) and label.
  2. Builds a classifier using ONLY n_events as a feature, and reports its
     AUC/accuracy/F1 -- if this single trivial feature gets anywhere close
     to Hybrid V2's reported 92% F1 / 95% accuracy, that's strong evidence
     the "hybrid" model isn't learning specific malicious behavior at all,
     just trace length.
  3. Re-runs the stat-features-only ablation with features normalized to be
     RATE-based (per-event) rather than raw counts, removing the trace-length
     confound, and reports whether performance holds up. If performance
     drops sharply once length is controlled for, that confirms the
     confound is driving most of the apparent signal.

Usage:
    python check_length_confound.py
"""

import json
import os
import numpy as np
from collections import Counter


def load_events(path):
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]


def count_events(path):
    """Just count events -- the single feature we're testing in isolation."""
    n = 0
    with open(path, 'r') as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def extract_count_features(events):
    """A subset of Hybrid V2's raw COUNT features (not the fraction/ratio
    ones), to check how much of their signal is just trace length."""
    n_events = len(events)
    event_types = Counter(e.get('type', '') for e in events)
    paths = [e.get('fname', '') for e in events if e.get('fname')]
    comms = [e.get('comm', '') for e in events]
    unique_files = set(paths)
    counts = {
        'n_events': n_events,
        'n_exec': event_types.get('exec', 0),
        'n_open': event_types.get('open', 0),
        'n_connect': event_types.get('connect', 0),
        'n_unique_files': len(unique_files),
        'n_tmp': sum(1 for p in paths if '/tmp/' in p or '/var/tmp/' in p),
        'n_python': sum(1 for p in paths if 'site-packages' in p or '.py' in p),
        'n_lib': sum(1 for p in paths if '/lib/' in p),
        'curl_wget': sum(1 for c in comms if 'curl' in c.lower() or 'wget' in c.lower()),
        'chmod_chown': sum(1 for c in comms if c.lower() in ['chmod', 'chown']),
        'base64_openssl': sum(1 for c in comms if c.lower() in ['base64', 'openssl']),
    }
    return counts


def main():
    CHECKPOINT_DIR = "models/checkpoints"
    split_path = os.path.join(CHECKPOINT_DIR, "split_info.json")
    if not os.path.exists(split_path):
        print(f"ERROR: {split_path} not found. Run train_with_split.py first.")
        return

    with open(split_path, 'r') as f:
        split_info = json.load(f)

    # Use train+val+test combined for a robust correlation estimate
    all_items = split_info['train'] + split_info['val'] + split_info['test']

    print(f"Loading {len(all_items)} samples...")
    rows = []
    for item in all_items:
        try:
            events = load_events(item['path'])
            feats = extract_count_features(events)
            feats['label'] = item['label']
            rows.append(feats)
        except Exception as e:
            print(f"  WARNING: failed on {item['path']}: {e}")
            continue

    labels = np.array([r['label'] for r in rows])
    n_events_arr = np.array([r['n_events'] for r in rows], dtype=np.float64)

    print(f"\n{'=' * 80}")
    print("STEP 1: Correlation between trace length (n_events) and label")
    print(f"{'=' * 80}")

    corr = np.corrcoef(n_events_arr, labels)[0, 1]
    print(f"Pearson correlation (n_events vs label): {corr:.4f}")
    print(f"  (label=1 is malicious; negative correlation means malicious")
    print(f"   traces tend to be SHORTER)")

    clean_n = n_events_arr[labels == 0]
    mal_n = n_events_arr[labels == 1]
    print(f"\n  Clean n_events:  mean={clean_n.mean():.1f}, median={np.median(clean_n):.1f}")
    print(f"  Malware n_events: mean={mal_n.mean():.1f}, median={np.median(mal_n):.1f}")

    print(f"\n{'=' * 80}")
    print("STEP 2: Classifier using ONLY n_events as a feature")
    print(f"{'=' * 80}")

    from sklearn.model_selection import train_test_split
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score, f1_score, accuracy_score

    X = n_events_arr.reshape(-1, 1)
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.3, random_state=42, stratify=labels
    )

    clf = LogisticRegression(class_weight='balanced')
    clf.fit(X_train, y_train)
    probs = clf.predict_proba(X_test)[:, 1]
    preds = (probs > 0.5).astype(int)

    auc = roc_auc_score(y_test, probs)
    f1 = f1_score(y_test, preds, zero_division=0)
    acc = accuracy_score(y_test, preds)

    print(f"Using n_events ALONE as the only feature:")
    print(f"  Accuracy: {acc:.2%}")
    print(f"  F1:       {f1:.2%}")
    print(f"  ROC-AUC:  {auc:.4f}")
    print(f"""
  If this single trivial feature gets anywhere close to Hybrid V2's
  reported 92% F1 / 95% accuracy, that's strong evidence the "hybrid"
  model is mostly keying off trace length, not specific malicious
  behavior like curl/wget, base64, or chmod usage.
""")

    print(f"{'=' * 80}")
    print("STEP 3: Rate-based (per-event) features, controlling for length")
    print(f"{'=' * 80}")

    # Convert every count feature to a per-event rate, removing the raw
    # trace-length signal while preserving BEHAVIORAL proportions.
    feature_keys = [k for k in rows[0].keys() if k not in ('label', 'n_events')]
    X_rate = []
    for r in rows:
        denom = max(1, r['n_events'])
        X_rate.append([r[k] / denom for k in feature_keys])
    X_rate = np.array(X_rate, dtype=np.float64)

    Xr_train, Xr_test, yr_train, yr_test = train_test_split(
        X_rate, labels, test_size=0.3, random_state=42, stratify=labels
    )
    mean = Xr_train.mean(axis=0, keepdims=True)
    std = Xr_train.std(axis=0, keepdims=True) + 1e-8
    Xr_train_n = (Xr_train - mean) / std
    Xr_test_n = (Xr_test - mean) / std

    clf2 = LogisticRegression(max_iter=2000, class_weight='balanced')
    clf2.fit(Xr_train_n, yr_train)
    probs2 = clf2.predict_proba(Xr_test_n)[:, 1]
    preds2 = (probs2 > 0.5).astype(int)

    auc2 = roc_auc_score(yr_test, probs2)
    f1_2 = f1_score(yr_test, preds2, zero_division=0)
    acc2 = accuracy_score(yr_test, preds2)

    print(f"Using RATE-based features ({', '.join(feature_keys)}):")
    print(f"  Accuracy: {acc2:.2%}")
    print(f"  F1:       {f1_2:.2%}")
    print(f"  ROC-AUC:  {auc2:.4f}")
    print(f"""
Interpretation:
  - Step 2 tells you how much signal trace length ALONE carries.
  - Step 3 tells you how much signal survives once every feature is
    expressed as a rate (removing the length confound). If Step 3's
    numbers are close to Step 2's, the "behavioral" features aren't
    adding much beyond what trace length already tells you. If Step 3
    is meaningfully better than Step 2, there IS real behavioral signal
    beyond just trace length -- worth knowing before trusting the 92% F1
    as evidence of learned malicious-behavior detection.
""")


if __name__ == "__main__":
    main()
