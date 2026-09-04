"""
QUT-DV25 to SCBF Format Converter

Converts QUT-DV25 opensnoop traces to SCBF-compatible JSONL format.

Usage:
    python scripts/convert_qutdv25.py                    # Full conversion
    python scripts/convert_qutdv25.py --dry-run          # Test without writing
    python scripts/convert_qutdv25.py --limit 5          # Convert only 5 samples per class
"""

import os
import json
import argparse
import sys
from pathlib import Path
from collections import defaultdict


# Base timestamp for synthetic timestamps
BASE_TIMESTAMP = 1000000000000  # Arbitrary base in nanoseconds
TIMESTAMP_INCREMENT = 100000    # 0.1ms between events


def parse_opensnoop_line(line):
    """
    Parse a single line from opensnoop trace.
    
    Format: PID  COMM  FD  ERR  PATH
    Example: 24584  pip    3   0 /home/Tanzir/.../file.py
    
    Returns dict with pid, comm, fd, err, path or None if invalid.
    """
    line = line.strip()
    
    # Skip empty lines
    if not line:
        return None
    
    # Skip header lines
    if 'PID' in line and 'COMM' in line and 'PATH' in line:
        return None
    
    parts = line.split(None, 4)  # Split on whitespace, max 5 parts
    
    if len(parts) < 5:
        return None
    
    pid_str, comm, fd_str, err_str, path = parts
    
    # Validate PID is numeric
    if not pid_str.isdigit():
        return None
    
    return {
        'pid': int(pid_str),
        'comm': comm,
        'fd': fd_str,
        'err': err_str,
        'path': path
    }


def read_pid_file(pid_file_path):
    """Read the first PID from PIDs file (may contain multiple PIDs)."""
    try:
        with open(pid_file_path, 'r') as f:
            # Read first line (first PID)
            first_line = f.readline().strip()
            if first_line.isdigit():
                return int(first_line)
    except Exception as e:
        print(f"  WARNING: Could not read PID from {pid_file_path}: {e}")
    
    return None


def convert_sample(opensnoop_path, pid_path, output_path, dry_run=False):
    """
    Convert a single QUT-DV25 sample to SCBF format.
    
    Args:
        opensnoop_path: Path to *_opensnoop_trace.txt file
        pid_path: Path to corresponding PID file
        output_path: Path to output JSONL file
        dry_run: If True, don't write output file
    
    Returns:
        dict with statistics (events_converted, events_skipped, etc.)
    """
    stats = {
        'success': False,
        'events_read': 0,
        'events_converted': 0,
        'events_skipped': 0,
        'error': None
    }
    
    # Read PID
    root_pid = read_pid_file(pid_path)
    if root_pid is None:
        stats['error'] = "Could not read PID"
        return stats
    
    # Parse opensnoop trace
    events = []
    current_ts = BASE_TIMESTAMP
    
    try:
        with open(opensnoop_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                stats['events_read'] += 1
                
                parsed = parse_opensnoop_line(line)
                
                if parsed is None:
                    stats['events_skipped'] += 1
                    continue
                
                # Create SCBF-format open event
                event = {
                    'type': 'open',
                    'pid': parsed['pid'],
                    'fname': parsed['path'],
                    'ts': current_ts
                }
                
                events.append(event)
                stats['events_converted'] += 1
                current_ts += TIMESTAMP_INCREMENT
    
    except Exception as e:
        stats['error'] = f"Error reading opensnoop file: {e}"
        return stats
    
    # Add synthetic root exec event at the beginning
    if events:
        root_exec = {
            'type': 'exec',
            'pid': root_pid,
            'ppid': 0,  # Root process has no parent
            'comm': 'pip',
            'ts': BASE_TIMESTAMP - TIMESTAMP_INCREMENT  # Before first open event
        }
        events.insert(0, root_exec)
    
    # Write JSONL output
    if not dry_run:
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                for event in events:
                    f.write(json.dumps(event) + '\n')
            
            stats['success'] = True
        
        except Exception as e:
            stats['error'] = f"Error writing output file: {e}"
            return stats
    else:
        # Dry run: just validate we can generate events
        stats['success'] = True
    
    return stats


def get_package_name(filename):
    """
    Extract package name from trace filename.
    
    Examples:
        robotlogger3_opensnoop_trace.txt -> robotlogger3
        aaiohttp-0.1.tar.gz_opensnoop_trace.txt -> aaiohttp-0.1.tar.gz
    """
    # Remove _opensnoop_trace.txt suffix
    name = filename.replace('_opensnoop_trace.txt', '')
    return name


def convert_dataset(base_dir, output_dir, label, limit=None, dry_run=False):
    """
    Convert all samples for a given label (benign or malicious).
    
    Args:
        base_dir: QUT-DV_Raw_Datasets directory path
        output_dir: Base output directory (data/)
        label: "benign" or "malicious"
        limit: Maximum number of samples to convert (None = all)
        dry_run: If True, don't write files
    
    Returns:
        dict with conversion statistics
    """
    print(f"\n{'='*80}")
    print(f"Converting {label.upper()} samples")
    print('='*80)
    
    if label == "benign":
        raw_dir = Path(base_dir) / "QUT-DV25_Benign_Raw_Data_Samples"
        output_subdir = Path(output_dir) / "qut_clean"
    else:  # malicious
        raw_dir = Path(base_dir) / "QUT-DV25_Malicious_Raw_Data_Samples"
        output_subdir = Path(output_dir) / "qut_malicious"
    
    opensnoop_dir = raw_dir / "QUT-DV25_Opensnoop_Traces"
    pids_dir = raw_dir / "QUT-DV25_PIDs"
    
    # Get list of opensnoop files
    opensnoop_files = [
        f for f in os.listdir(str(opensnoop_dir)) 
        if f.endswith('_opensnoop_trace.txt') and not f.startswith('._')
    ]
    
    if limit:
        opensnoop_files = opensnoop_files[:limit]
    
    print(f"Found {len(opensnoop_files)} samples to convert")
    
    stats = {
        'total': len(opensnoop_files),
        'success': 0,
        'failed': 0,
        'total_events_converted': 0,
        'total_events_skipped': 0,
        'errors': []
    }
    
    # Convert each sample
    for i, opensnoop_file in enumerate(opensnoop_files, 1):
        pkg_name = get_package_name(opensnoop_file)
        
        opensnoop_path = opensnoop_dir / opensnoop_file
        pid_file = 'traced_pids_' + pkg_name + '.txt'
        pid_path = pids_dir / pid_file
        output_file = pkg_name + '.jsonl'
        output_path = output_subdir / output_file
        
        # Check if PID file exists
        if not os.path.exists(str(pid_path)):
            print(f"[{i}/{len(opensnoop_files)}] SKIP {pkg_name}: PID file not found")
            stats['failed'] += 1
            stats['errors'].append(f"{pkg_name}: PID file not found")
            continue
        
        # Convert
        result = convert_sample(
            str(opensnoop_path),
            str(pid_path),
            str(output_path),
            dry_run=dry_run
        )
        
        if result['success']:
            stats['success'] += 1
            stats['total_events_converted'] += result['events_converted']
            stats['total_events_skipped'] += result['events_skipped']
            
            status = "DRY-RUN" if dry_run else "OK"
            print(f"[{i}/{len(opensnoop_files)}] {status} {pkg_name}: "
                  f"{result['events_converted']} events "
                  f"({result['events_skipped']} skipped)")
        else:
            stats['failed'] += 1
            stats['errors'].append(f"{pkg_name}: {result['error']}")
            print(f"[{i}/{len(opensnoop_files)}] FAIL {pkg_name}: {result['error']}")
    
    return stats


def main():
    """Main conversion routine."""
    parser = argparse.ArgumentParser(
        description='Convert QUT-DV25 dataset to SCBF format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Full conversion
    python scripts/convert_qutdv25.py
    
    # Dry run (test without writing)
    python scripts/convert_qutdv25.py --dry-run
    
    # Convert only first 5 samples per class
    python scripts/convert_qutdv25.py --limit 5
    
    # Custom paths
    python scripts/convert_qutdv25.py --input QUT-DV25_Datasets/QUT-DV_Raw_Datasets --output data
        '''
    )
    
    parser.add_argument(
        '--input',
        type=str,
        default=None,
        help='Path to QUT-DV_Raw_Datasets directory (default: QUT-DV25_Datasets/QUT-DV_Raw_Datasets)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='data',
        help='Output directory for converted JSONL files (default: data/)'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Limit number of samples to convert per class (default: all)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Test conversion without writing output files'
    )
    
    args = parser.parse_args()
    
    # Determine input path
    if args.input:
        input_dir = args.input
    else:
        script_dir = Path(__file__).parent.parent
        input_dir = script_dir / "QUT-DV25_Datasets" / "QUT-DV_Raw_Datasets"
    
    # Validate input directory
    if not os.path.exists(input_dir):
        print(f"ERROR: Input directory not found: {input_dir}")
        sys.exit(1)
    
    benign_dir = Path(input_dir) / "QUT-DV25_Benign_Raw_Data_Samples"
    malicious_dir = Path(input_dir) / "QUT-DV25_Malicious_Raw_Data_Samples"
    
    if not benign_dir.exists() or not malicious_dir.exists():
        print(f"ERROR: Expected subdirectories not found in {input_dir}")
        print(f"  Expected: QUT-DV25_Benign_Raw_Data_Samples/")
        print(f"  Expected: QUT-DV25_Malicious_Raw_Data_Samples/")
        sys.exit(1)
    
    print("\n" + "="*80)
    print("QUT-DV25 to SCBF Converter")
    print("="*80)
    print(f"\nInput directory: {input_dir}")
    print(f"Output directory: {args.output}")
    
    if args.dry_run:
        print("\n⚠️  DRY RUN MODE - No files will be written")
    
    if args.limit:
        print(f"\nLimit: {args.limit} samples per class")
    
    # Convert benign samples
    benign_stats = convert_dataset(
        base_dir=input_dir,
        output_dir=args.output,
        label="benign",
        limit=args.limit,
        dry_run=args.dry_run
    )
    
    # Convert malicious samples
    malicious_stats = convert_dataset(
        base_dir=input_dir,
        output_dir=args.output,
        label="malicious",
        limit=args.limit,
        dry_run=args.dry_run
    )
    
    # Summary
    print(f"\n{'='*80}")
    print("CONVERSION SUMMARY")
    print('='*80)
    
    total_success = benign_stats['success'] + malicious_stats['success']
    total_failed = benign_stats['failed'] + malicious_stats['failed']
    total_events = benign_stats['total_events_converted'] + malicious_stats['total_events_converted']
    
    print(f"\nBenign samples:")
    print(f"  Success: {benign_stats['success']}")
    print(f"  Failed: {benign_stats['failed']}")
    print(f"  Events converted: {benign_stats['total_events_converted']:,}")
    
    print(f"\nMalicious samples:")
    print(f"  Success: {malicious_stats['success']}")
    print(f"  Failed: {malicious_stats['failed']}")
    print(f"  Events converted: {malicious_stats['total_events_converted']:,}")
    
    print(f"\nTOTAL:")
    print(f"  Success: {total_success}")
    print(f"  Failed: {total_failed}")
    print(f"  Total events: {total_events:,}")
    
    if total_events > 0:
        avg_events = total_events / total_success if total_success > 0 else 0
        print(f"  Average events/sample: {avg_events:.1f}")
    
    # Print errors if any
    all_errors = benign_stats['errors'] + malicious_stats['errors']
    if all_errors:
        print(f"\nErrors ({len(all_errors)}):")
        for error in all_errors[:10]:  # Show first 10
            print(f"  - {error}")
        if len(all_errors) > 10:
            print(f"  ... and {len(all_errors) - 10} more")
    
    if not args.dry_run:
        print(f"\nOutput files written to:")
        print(f"  {args.output}/qut_clean/*.jsonl")
        print(f"  {args.output}/qut_malicious/*.jsonl")
        print(f"\nNext step: python scripts/validate_qutdv25.py")
    else:
        print(f"\n⚠️  DRY RUN COMPLETE - No files were written")
        print(f"To convert for real, run without --dry-run flag")
    
    print("\n" + "="*80 + "\n")
    
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
