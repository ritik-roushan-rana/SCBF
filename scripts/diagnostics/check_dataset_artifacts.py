"""
Check if malicious vs benign traces have SYSTEMATIC collection differences
(dataset artifacts) rather than genuine behavioral differences.

If a linear model gets 98%+ F1, either:
1. Malware really has obvious different behavior (great!)
2. Or the traces were collected in different environments/tools
   creating systematic artifacts unrelated to malicious behavior

This script checks for:
- Different process names in the collection environment
- Different file path patterns
- Different unique identifiers
- Different collection tool signatures
"""

import json
import glob
from collections import Counter, defaultdict


def load_events(path, max_events=1000):
    events = []
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if i >= max_events:
                break
            events.append(json.loads(line))
    return events


def get_signature_features(events):
    """Extract features that indicate collection environment, not behavior."""
    if not events:
        return {}
    
    # Unique paths accessed
    paths = [e.get('fname', '') for e in events if e.get('fname')]
    commands = [e.get('comm', '') for e in events]
    
    # Root directories touched
    root_dirs = Counter()
    for p in paths:
        parts = p.split('/')
        if len(parts) >= 2:
            root = '/' + parts[1] if parts[0] == '' else parts[0]
            root_dirs[root] += 1
    
    # Common commands
    comm_counts = Counter(commands)
    
    # Path prefixes
    prefix_counts = Counter()
    for p in paths[:100]:  # First 100 paths
        parts = p.split('/')
        if len(parts) >= 3:
            prefix = '/'.join(parts[:3])
            prefix_counts[prefix] += 1
    
    return {
        'top_root_dirs': dict(root_dirs.most_common(5)),
        'top_commands': dict(comm_counts.most_common(5)),
        'top_prefixes': dict(prefix_counts.most_common(3)),
    }


def main():
    print("=" * 80)
    print("DATASET ARTIFACT ANALYSIS")
    print("=" * 80)
    
    clean_files = glob.glob("data/zenodo_13746167/benign/traces/*.jsonl")[:30]
    mal_files = glob.glob("data/zenodo_13746167/malware/traces/*.jsonl")[:30]
    
    print(f"\nAnalyzing {len(clean_files)} clean and {len(mal_files)} malware traces")
    print("(sampling first 30 files from each)\n")
    
    # Aggregate signatures
    clean_root_dirs = Counter()
    mal_root_dirs = Counter()
    clean_commands = Counter()
    mal_commands = Counter()
    clean_prefixes = Counter()
    mal_prefixes = Counter()
    
    for path in clean_files:
        try:
            events = load_events(path, max_events=500)
            sig = get_signature_features(events)
            clean_root_dirs.update(sig['top_root_dirs'])
            clean_commands.update(sig['top_commands'])
            clean_prefixes.update(sig['top_prefixes'])
        except:
            continue
    
    for path in mal_files:
        try:
            events = load_events(path, max_events=500)
            sig = get_signature_features(events)
            mal_root_dirs.update(sig['top_root_dirs'])
            mal_commands.update(sig['top_commands'])
            mal_prefixes.update(sig['top_prefixes'])
        except:
            continue
    
    # Show differences
    print("=" * 80)
    print("ROOT DIRECTORIES ACCESSED")
    print("=" * 80)
    all_roots = set(clean_root_dirs.keys()) | set(mal_root_dirs.keys())
    print(f"\n{'Directory':<20} {'Clean':<15} {'Malware':<15} {'Notes'}")
    print("-" * 80)
    for root in sorted(all_roots):
        c = clean_root_dirs.get(root, 0)
        m = mal_root_dirs.get(root, 0)
        notes = ""
        if c == 0 and m > 0:
            notes = "⚠️  ONLY IN MALWARE"
        elif m == 0 and c > 0:
            notes = "⚠️  ONLY IN CLEAN"
        elif c > 0 and m > 0 and (c > 10 * m or m > 10 * c):
            notes = "⚠️  10x DIFFERENCE"
        print(f"{root:<20} {c:<15} {m:<15} {notes}")
    
    print("\n" + "=" * 80)
    print("TOP COMMANDS")
    print("=" * 80)
    all_commands = set(clean_commands.keys()) | set(mal_commands.keys())
    print(f"\n{'Command':<20} {'Clean':<15} {'Malware':<15} {'Notes'}")
    print("-" * 80)
    top_commands = sorted(
        all_commands,
        key=lambda c: max(clean_commands.get(c, 0), mal_commands.get(c, 0)),
        reverse=True
    )[:15]
    for cmd in top_commands:
        c = clean_commands.get(cmd, 0)
        m = mal_commands.get(cmd, 0)
        notes = ""
        if c == 0 and m > 0:
            notes = "⚠️  ONLY IN MALWARE"
        elif m == 0 and c > 0:
            notes = "⚠️  ONLY IN CLEAN"
        print(f"{cmd:<20} {c:<15} {m:<15} {notes}")
    
    print("\n" + "=" * 80)
    print("PATH PREFIXES")
    print("=" * 80)
    all_prefixes = set(clean_prefixes.keys()) | set(mal_prefixes.keys())
    top_prefixes = sorted(
        all_prefixes,
        key=lambda c: max(clean_prefixes.get(c, 0), mal_prefixes.get(c, 0)),
        reverse=True
    )[:15]
    print(f"\n{'Path Prefix':<40} {'Clean':<10} {'Malware':<10} {'Notes'}")
    print("-" * 80)
    for prefix in top_prefixes:
        c = clean_prefixes.get(prefix, 0)
        m = mal_prefixes.get(prefix, 0)
        notes = ""
        if c == 0 and m > 5:
            notes = "⚠️  ONLY IN MALWARE"
        elif m == 0 and c > 5:
            notes = "⚠️  ONLY IN CLEAN"
        print(f"{prefix:<40} {c:<10} {m:<10} {notes}")
    
    print("\n" + "=" * 80)
    print("VERDICT")
    print("=" * 80)
    
    # Check for suspicious patterns
    unique_to_clean = []
    unique_to_mal = []
    
    for root in all_roots:
        c = clean_root_dirs.get(root, 0)
        m = mal_root_dirs.get(root, 0)
        if c == 0 and m > 3:
            unique_to_mal.append(f"'{root}' directory")
        elif m == 0 and c > 3:
            unique_to_clean.append(f"'{root}' directory")
    
    for prefix in top_prefixes:
        c = clean_prefixes.get(prefix, 0)
        m = mal_prefixes.get(prefix, 0)
        if c == 0 and m > 5:
            unique_to_mal.append(f"'{prefix}'")
        elif m == 0 and c > 5:
            unique_to_clean.append(f"'{prefix}'")
    
    if unique_to_clean or unique_to_mal:
        print("⚠️  POTENTIAL DATASET ARTIFACTS DETECTED:")
        if unique_to_clean:
            print(f"\n   Only in CLEAN traces:")
            for item in unique_to_clean[:5]:
                print(f"     - {item}")
        if unique_to_mal:
            print(f"\n   Only in MALWARE traces:")
            for item in unique_to_mal[:5]:
                print(f"     - {item}")
        
        print("""
   This suggests the datasets may have been collected in different
   environments/configurations, creating artifacts unrelated to
   actual malicious behavior. The 98% F1 might be detecting:
   - Different sandboxing tools
   - Different Python versions
   - Different filesystem layouts
   - Different collection scripts
   
   To trust the results, both datasets should be collected in
   IDENTICAL environments with only the package being different.
""")
    else:
        print("✓ NO OBVIOUS ARTIFACTS DETECTED")
        print("  Both classes show similar collection environment.")
        print("  High F1 likely reflects genuine behavioral differences.")


if __name__ == "__main__":
    main()
