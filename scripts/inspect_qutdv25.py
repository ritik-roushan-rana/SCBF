"""
QUT-DV25 Dataset Inspector

Analyzes the QUT-DV25 dataset structure and provides statistics
without modifying any files.
"""

import os
import csv
import sys
from pathlib import Path
from collections import defaultdict


def inspect_processed_csv(csv_path):
    """Inspect processed CSV files for package counts and labels."""
    print(f"\n{'='*80}")
    print(f"Inspecting: {os.path.basename(csv_path)}")
    print('='*80)
    
    if not os.path.exists(csv_path):
        print(f"ERROR: File not found: {csv_path}")
        return None
    
    stats = {
        'total': 0,
        'benign': 0,  # Level 0
        'malicious': 0,  # Level 1
        'unknown': 0,
        'packages': []
    }
    
    with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            stats['total'] += 1
            pkg_name = row.get('Package_Name', 'unknown')
            level = row.get('Level', '').strip()
            
            stats['packages'].append({
                'name': pkg_name,
                'level': level
            })
            
            if level == '0':
                stats['benign'] += 1
            elif level == '1':
                stats['malicious'] += 1
            else:
                stats['unknown'] += 1
    
    print(f"Total packages: {stats['total']}")
    print(f"Benign (Level 0): {stats['benign']}")
    print(f"Malicious (Level 1): {stats['malicious']}")
    print(f"Unknown level: {stats['unknown']}")
    
    return stats


def count_raw_samples(raw_dir, label):
    """Count raw trace files for a given label."""
    print(f"\n{'='*80}")
    print(f"Inspecting Raw {label} Samples")
    print('='*80)
    
    if not os.path.exists(raw_dir):
        print(f"ERROR: Directory not found: {raw_dir}")
        return None
    
    stats = {
        'total_samples': 0,
        'trace_types': defaultdict(int),
        'sample_names': []
    }
    
    # Check each trace type directory
    trace_types = [
        'QUT-DV25_Opensnoop_Traces',
        'QUT-DV25_Installation_Traces',
        'QUT-DV25_PIDs',
        'QUT-DV25_TCP_Traces',
        'QUT-DV25_Filetop_Traces',
        'QUT-DV25_Pattern_Traces'
    ]
    
    for trace_type in trace_types:
        trace_dir = os.path.join(raw_dir, trace_type)
        if os.path.exists(trace_dir):
            files = [f for f in os.listdir(trace_dir) if not f.startswith('._')]
            stats['trace_types'][trace_type] = len(files)
    
    # Use opensnoop as reference count (most complete)
    opensnoop_dir = os.path.join(raw_dir, 'QUT-DV25_Opensnoop_Traces')
    if os.path.exists(opensnoop_dir):
        files = [f for f in os.listdir(opensnoop_dir) if not f.startswith('._')]
        stats['total_samples'] = len(files)
        stats['sample_names'] = sorted([f.replace('_opensnoop_trace.txt', '') for f in files[:10]])
    
    print(f"Total {label} samples: {stats['total_samples']}")
    print(f"\nTrace types available:")
    for trace_type, count in sorted(stats['trace_types'].items()):
        print(f"  {trace_type}: {count} files")
    
    print(f"\nFirst 10 package names:")
    for name in stats['sample_names'][:10]:
        print(f"  - {name}")
    
    return stats


def inspect_sample_file(filepath, max_lines=30):
    """Inspect a single trace file."""
    print(f"\n{'='*80}")
    print(f"Sample File: {os.path.basename(filepath)}")
    print('='*80)
    
    if not os.path.exists(filepath):
        print(f"ERROR: File not found: {filepath}")
        return
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = []
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            lines.append(line.rstrip())
    
    print(f"First {len(lines)} lines:\n")
    for i, line in enumerate(lines, 1):
        print(f"{i:3d}: {line}")
    
    # File statistics
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        total_lines = sum(1 for _ in f)
    
    file_size = os.path.getsize(filepath)
    print(f"\nFile statistics:")
    print(f"  Total lines: {total_lines}")
    print(f"  File size: {file_size:,} bytes ({file_size/1024:.1f} KB)")


def analyze_opensnoop_format(opensnoop_dir, num_samples=5):
    """Analyze opensnoop trace format across multiple samples."""
    print(f"\n{'='*80}")
    print("Opensnoop Trace Format Analysis")
    print('='*80)
    
    if not os.path.exists(opensnoop_dir):
        print(f"ERROR: Directory not found: {opensnoop_dir}")
        return
    
    files = [f for f in os.listdir(opensnoop_dir) if f.endswith('.txt') and not f.startswith('._')]
    files = files[:num_samples]
    
    stats = {
        'samples_analyzed': 0,
        'avg_events': 0,
        'min_events': float('inf'),
        'max_events': 0,
        'total_events': 0,
        'common_pids': defaultdict(int)
    }
    
    for filename in files:
        filepath = os.path.join(opensnoop_dir, filename)
        
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = [line.strip() for line in f if line.strip()]
            # Skip header lines (usually contain "PID", "COMM", etc.)
            data_lines = [l for l in lines if not ('PID' in l and 'COMM' in l)]
            
            event_count = len(data_lines)
            stats['samples_analyzed'] += 1
            stats['total_events'] += event_count
            stats['min_events'] = min(stats['min_events'], event_count)
            stats['max_events'] = max(stats['max_events'], event_count)
            
            # Extract PIDs from first column
            for line in data_lines[:100]:  # Check first 100 events
                parts = line.split()
                if len(parts) >= 2 and parts[0].isdigit():
                    stats['common_pids'][parts[0]] += 1
    
    if stats['samples_analyzed'] > 0:
        stats['avg_events'] = stats['total_events'] / stats['samples_analyzed']
    
    print(f"Analyzed {stats['samples_analyzed']} samples:")
    print(f"  Average events/sample: {stats['avg_events']:.1f}")
    print(f"  Min events: {stats['min_events']}")
    print(f"  Max events: {stats['max_events']}")
    print(f"  Total events: {stats['total_events']:,}")
    
    # Most common PIDs
    if stats['common_pids']:
        print(f"\nMost common PIDs (from first 100 events per file):")
        for pid, count in sorted(stats['common_pids'].items(), key=lambda x: -x[1])[:10]:
            print(f"  PID {pid}: {count} occurrences")
    
    return stats


def main():
    """Main inspection routine."""
    print("\n" + "="*80)
    print("QUT-DV25 Dataset Inspector")
    print("="*80)
    
    # Base paths
    base_dir = Path(__file__).parent.parent / "QUT-DV25_Datasets"
    
    if not base_dir.exists():
        print(f"\nERROR: QUT-DV25_Datasets not found at: {base_dir}")
        print("Expected location: /Users/shield/Downloads/scbf/QUT-DV25_Datasets/")
        sys.exit(1)
    
    print(f"\nDataset location: {base_dir}")
    
    # 1. Inspect processed CSV
    processed_dir = base_dir / "QUT-DV25_Processed_Datasets"
    install_csv = processed_dir / "QUT-DV25_Install_Traces" / "QUT-DV25_Install_Traces.csv"
    install_stats = inspect_processed_csv(str(install_csv))
    
    # 2. Inspect raw benign samples
    raw_dir = base_dir / "QUT-DV_Raw_Datasets"
    benign_dir = raw_dir / "QUT-DV25_Benign_Raw_Data_Samples"
    benign_stats = count_raw_samples(str(benign_dir), "Benign")
    
    # 3. Inspect raw malicious samples
    malicious_dir = raw_dir / "QUT-DV25_Malicious_Raw_Data_Samples"
    malicious_stats = count_raw_samples(str(malicious_dir), "Malicious")
    
    # 4. Analyze opensnoop format (benign)
    opensnoop_benign = benign_dir / "QUT-DV25_Opensnoop_Traces"
    opensnoop_stats_benign = analyze_opensnoop_format(str(opensnoop_benign), num_samples=10)
    
    # 5. Analyze opensnoop format (malicious)
    opensnoop_malicious = malicious_dir / "QUT-DV25_Opensnoop_Traces"
    opensnoop_stats_malicious = analyze_opensnoop_format(str(opensnoop_malicious), num_samples=10)
    
    # 6. Inspect sample files
    # Sample benign opensnoop
    benign_files = [f for f in os.listdir(str(opensnoop_benign)) if f.endswith('.txt') and not f.startswith('._')]
    if benign_files:
        sample_file = opensnoop_benign / benign_files[0]
        inspect_sample_file(str(sample_file), max_lines=30)
    
    # Sample malicious opensnoop
    malicious_files = [f for f in os.listdir(str(opensnoop_malicious)) if f.endswith('.txt') and not f.startswith('._')]
    if malicious_files:
        sample_file = opensnoop_malicious / malicious_files[0]
        inspect_sample_file(str(sample_file), max_lines=30)
    
    # 7. Summary
    print(f"\n{'='*80}")
    print("SUMMARY")
    print('='*80)
    
    if install_stats:
        print(f"\nProcessed CSV Statistics:")
        print(f"  Total packages in CSV: {install_stats['total']}")
        print(f"  Benign (Level 0): {install_stats['benign']}")
        print(f"  Malicious (Level 1): {install_stats['malicious']}")
    
    if benign_stats and malicious_stats:
        print(f"\nRaw Sample Counts:")
        print(f"  Benign samples: {benign_stats['total_samples']}")
        print(f"  Malicious samples: {malicious_stats['total_samples']}")
        print(f"  Total raw samples: {benign_stats['total_samples'] + malicious_stats['total_samples']}")
    
    if opensnoop_stats_benign and opensnoop_stats_malicious:
        total_analyzed = opensnoop_stats_benign['samples_analyzed'] + opensnoop_stats_malicious['samples_analyzed']
        total_events = opensnoop_stats_benign['total_events'] + opensnoop_stats_malicious['total_events']
        avg_events = total_events / total_analyzed if total_analyzed > 0 else 0
        
        print(f"\nOpensnoop Event Statistics:")
        print(f"  Samples analyzed: {total_analyzed}")
        print(f"  Average events/sample: {avg_events:.1f}")
        print(f"  Total events: {total_events:,}")
    
    print(f"\nConversion readiness: ✅ READY")
    print(f"\nNext step: python scripts/convert_qutdv25.py")
    print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    main()
