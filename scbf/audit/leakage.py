"""
Dataset leakage audit. RUN THIS BEFORE YOU TRUST ANY METRIC.

This exists because of a real failure. In the zenodo_13746167 collection,
97.2% of benign traces contained /dev/pts and 0% of malicious ones did --
the two classes had been captured through different harness invocations,
one with a TTY attached and one without. The consequences:

    single rule "malicious if <5 /dev accesses"   -> 96.48% F1
    trained hybrid TGN                            -> 92.31% F1
    same model, artifact removed                  -> 52.53% F1

The model was detecting the collection environment, not malicious behavior.
Nothing in the pipeline noticed, because every metric looked excellent.

This audit looks for the shape of that failure:

  1. Token leakage   - path/comm tokens that appear in almost all traces
                       of one class and almost none of the other.
  2. Feature leakage - single features whose class value ranges are
                       disjoint or near-disjoint (an unbeatable threshold).
  3. Environment     - capture fingerprints that differ by class.

Any of these means a metric computed on this dataset is measuring
collection, not behavior.

Usage:
    python3 -m scbf.audit.leakage --traces data/traces
    python3 -m scbf.audit.leakage --traces data/traces --strict   # exit 1 on fail
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

# A token in >= this fraction of one class and <= this fraction of the other
# is a giveaway, not a behavior.
PRESENT = 0.90
ABSENT = 0.10
# A single feature scoring above this AUC deserves an explanation.
AUC_ALARM = 0.95


def iter_traces(root: Path):
    """Only successfully-installed traces: auditing failed installs would
    both miss the real question and flag failure-shape differences that
    are excluded from training anyway."""
    from scbf.dataset import ok_traces
    for item in ok_traces(root, require_manifest=False):
        yield Path(item["path"]), item["label"]


def trace_tokens(path: Path, max_events: int = 20000) -> set:
    """Distinctive tokens in one trace: path prefixes and process names."""
    toks = set()
    try:
        with open(path) as f:
            for i, line in enumerate(f):
                if i >= max_events:
                    break
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                comm = e.get("comm", "")
                if comm:
                    toks.add(f"comm:{comm}")
                fn = e.get("fname", "")
                if fn.startswith("/"):
                    parts = fn.split("/")
                    for depth in (2, 3):
                        if len(parts) > depth:
                            toks.add("path:" + "/".join(parts[:depth + 1]))
                if e.get("type") == "connect" and e.get("dport"):
                    toks.add(f"port:{e['dport']}")
    except Exception:
        pass
    return toks


def audit_tokens(root: Path) -> list:
    counts = {0: Counter(), 1: Counter()}
    totals = {0: 0, 1: 0}
    for path, label in iter_traces(root):
        totals[label] += 1
        for t in trace_tokens(path):
            counts[label][t] += 1

    if not totals[0] or not totals[1]:
        return [("FATAL", "one class has no traces", "")]

    findings = []
    for tok in set(counts[0]) | set(counts[1]):
        f0 = counts[0][tok] / totals[0]
        f1 = counts[1][tok] / totals[1]
        if (f0 >= PRESENT and f1 <= ABSENT) or (f1 >= PRESENT and f0 <= ABSENT):
            findings.append((tok, f0, f1))
    findings.sort(key=lambda r: -abs(r[1] - r[2]))
    return findings, totals


def audit_features(root: Path, feature_fn) -> list:
    """Single features that separate the classes suspiciously well."""
    from sklearn.metrics import roc_auc_score

    X, Y = [], []
    for path, label in iter_traces(root):
        try:
            with open(path) as f:
                events = [json.loads(l) for l in f]
        except Exception:
            continue
        if not events:
            continue
        X.append(feature_fn(events))
        Y.append(label)
    if not X:
        return []
    X, Y = np.array(X), np.array(Y)

    out = []
    for i in range(X.shape[1]):
        col = X[:, i]
        if np.all(col == col[0]):
            continue
        auc = roc_auc_score(Y, col)
        auc = max(auc, 1 - auc)
        c, m = col[Y == 0], col[Y == 1]
        disjoint = bool(c.max() < m.min() or m.max() < c.min())
        if disjoint or auc >= AUC_ALARM:
            out.append((i, auc, disjoint, (c.min(), c.max()), (m.min(), m.max())))
    return sorted(out, key=lambda r: -r[1])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--traces", required=True, type=Path)
    ap.add_argument("--strict", action="store_true",
                    help="Exit non-zero if anything is flagged.")
    ap.add_argument("--skip-features", action="store_true")
    args = ap.parse_args()

    print("=" * 78)
    print("SCBF DATASET LEAKAGE AUDIT")
    print("=" * 78)

    failed = False

    print("\n[1] Token leakage (present in one class, absent in the other)")
    print("-" * 78)
    result = audit_tokens(args.traces)
    if result and result[0] and result[0][0] == "FATAL":
        print(f"  FATAL: {result[0][1]}")
        sys.exit(1)
    findings, totals = result
    print(f"    benign traces={totals[0]}  malicious traces={totals[1]}")
    if findings:
        failed = True
        print(f"\n  {len(findings)} LEAKING TOKEN(S) -- metrics on this data are not trustworthy:\n")
        print(f"    {'token':<46}{'benign':>10}{'malicious':>11}")
        for tok, f0, f1 in findings[:15]:
            print(f"    {tok[:44]:<46}{f0:>9.1%}{f1:>11.1%}")
        print("\n    A token like this lets a one-line rule score near-perfect F1.")
        print("    Fix the CAPTURE, not the model.")
    else:
        print("    ✓ no token separates the classes")

    if not args.skip_features:
        print("\n[2] Single-feature separation")
        print("-" * 78)
        try:
            from scbf.features.statistical import extract_features, FEATURE_NAMES
            feats = audit_features(args.traces, extract_features)
            if feats:
                failed = True
                print(f"  {len(feats)} SUSPICIOUS FEATURE(S):\n")
                for i, auc, disjoint, cr, mr in feats[:12]:
                    name = FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f"feat_{i}"
                    tag = "** DISJOINT **" if disjoint else "high AUC"
                    print(f"    {name:<22} AUC={auc:.4f}  benign[{cr[0]:.4g},{cr[1]:.4g}] "
                          f"malicious[{mr[0]:.4g},{mr[1]:.4g}]  {tag}")
            else:
                print("    ✓ no single feature separates the classes outright")
        except ImportError:
            print("    (skipped: feature module unavailable)")

    print("\n[3] Capture environment")
    print("-" * 78)
    env_path = args.traces / "environment.json"
    if env_path.exists():
        env = json.loads(env_path.read_text())
        print(f"    kernel={env.get('kernel')}  stdout_isatty={env.get('stdout_isatty')}")
        print("    ✓ single environment fingerprint for the whole collection")
    else:
        print("    ⚠ no environment.json -- cannot prove both classes shared a harness")

    print("\n" + "=" * 78)
    if failed:
        print("VERDICT: LEAKAGE DETECTED. Do not report metrics from this dataset.")
        print("=" * 78)
        if args.strict:
            sys.exit(1)
    else:
        print("VERDICT: CLEAN. No collection artifact found.")
        print("=" * 78)


if __name__ == "__main__":
    main()
