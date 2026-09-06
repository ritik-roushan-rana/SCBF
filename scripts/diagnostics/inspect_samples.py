"""
Manual inspection: sanity-check the top separating features.

The rate-normalized ablation gets 98%+ F1 from features like dev_ratio,
system_ratio, proc_ratio, home_ratio, hidden_ratio. Some of these (home
directory / dotfile targeting) look like real attacker behavior. Others
(dev/system/proc access predicting BENIGN) look like they could reflect a
different execution environment or collection methodology for the two
classes, rather than actual malicious intent.

The only way to tell the difference is to look at real examples. This
script prints a side-by-side sample of clean vs malicious traces,
highlighting the actual paths/commands behind the top features, so you can
eyeball whether the pattern looks like genuine attacker behavior or an
artifact of how each class was captured (e.g. different sandbox, different
execution harness, different user account, truncated execution).

Usage:
    python inspect_samples.py [--n 5]
"""

import json
import os
import sys
import random
from collections import Counter


def load_events(path):
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]


def summarize_trace(path, label):
    events = load_events(path)
    n_events = len(events)
    paths = [e.get('fname', '') for e in events if e.get('fname')]
    comms = [e.get('comm', '') for e in events]
    n_paths = max(1, len(paths))

    dev_paths = [p for p in paths if p.startswith('/dev/')]
    system_paths = [p for p in paths if p.startswith('/usr/') or p.startswith('/etc/')]
    proc_paths = [p for p in paths if p.startswith('/proc/')]
    home_paths = [p for p in paths if '/home/' in p or p.startswith('~')]
    hidden_paths = [p for p in paths if '/.' in p]

    print(f"\n{'-' * 80}")
    print(f"[{label.upper()}] {path}")
    print(f"{'-' * 80}")
    print(f"  Total events: {n_events}")
    print(f"  dev_ratio:    {len(dev_paths) / n_paths:.3f}  ({len(dev_paths)}/{n_paths})")
    print(f"  system_ratio: {len(system_paths) / n_paths:.3f}  ({len(system_paths)}/{n_paths})")
    print(f"  proc_ratio:   {len(proc_paths) / n_paths:.3f}  ({len(proc_paths)}/{n_paths})")
    print(f"  home_ratio:   {len(home_paths) / n_paths:.3f}  ({len(home_paths)}/{n_paths})")
    print(f"  hidden_ratio: {len(hidden_paths) / n_paths:.3f}  ({len(hidden_paths)}/{n_paths})")
    print(f"\n  Sample /dev paths:    {dev_paths[:3]}")
    print(f"  Sample system paths:  {system_paths[:3]}")
    print(f"  Sample home paths:    {home_paths[:3]}")
    print(f"  Sample hidden paths:  {hidden_paths[:3]}")
    print(f"\n  First 5 events (raw):")
    for e in events[:5]:
        print(f"    {json.dumps(e)}")
    print(f"\n  Last 5 events (raw):")
    for e in events[-5:]:
        print(f"    {json.dumps(e)}")

    comm_counts = Counter(comms)
    print(f"\n  Top commands: {comm_counts.most_common(5)}")


def main():
    n = 5
    if '--n' in sys.argv:
        n = int(sys.argv[sys.argv.index('--n') + 1])

    CHECKPOINT_DIR = "models/checkpoints"
    split_path = os.path.join(CHECKPOINT_DIR, "split_info.json")
    if not os.path.exists(split_path):
        print(f"ERROR: {split_path} not found. Run train_with_split.py first.")
        return

    with open(split_path, 'r') as f:
        split_info = json.load(f)

    all_items = split_info['train'] + split_info['val'] + split_info['test']
    clean_items = [x for x in all_items if x['label'] == 0]
    mal_items = [x for x in all_items if x['label'] == 1]

    random.seed(0)
    clean_sample = random.sample(clean_items, min(n, len(clean_items)))
    mal_sample = random.sample(mal_items, min(n, len(mal_items)))

    print("=" * 80)
    print(f"INSPECTING {n} CLEAN SAMPLES")
    print("=" * 80)
    for item in clean_sample:
        try:
            summarize_trace(item['path'], 'clean')
        except Exception as e:
            print(f"  WARNING: failed on {item['path']}: {e}")

    print("\n\n" + "=" * 80)
    print(f"INSPECTING {n} MALICIOUS SAMPLES")
    print("=" * 80)
    for item in mal_sample:
        try:
            summarize_trace(item['path'], 'malicious')
        except Exception as e:
            print(f"  WARNING: failed on {item['path']}: {e}")

    print("""
WHAT TO LOOK FOR:

  1. Do malicious traces look like they were captured the SAME WAY as
     clean traces (same install tool, same sandbox, same user account)?
     Check the first/last few raw events -- do clean traces start with a
     package manager invocation (pip/npm) while malicious traces start
     differently (e.g. a bare script execution)?

  2. Is dev_ratio/system_ratio near-zero for EVERY malicious sample and
     consistently nonzero for EVERY clean sample? A pattern that clean-cut
     usually means "different collection pipeline", not "different
     behavior" -- real attacker behavior is rarely THAT consistent across
     unrelated malware samples.

  3. Do home_ratio / hidden_ratio spikes in malicious samples show ACTUAL
     credential-theft-looking paths (.ssh/id_rsa, .aws/credentials,
     .npmrc), or just incidental home-directory noise?
""")


if __name__ == "__main__":
    main()
