"""
Validate QUT-DV25 converted JSONL files.

Checks format, structure, and compatibility with SCBF expectations
WITHOUT requiring PyTorch/TGN (can run on macOS).
"""

import json
import glob
import sys
from pathlib import Path
from collections import defaultdict


def validate_event(event, event_index):
    """
    Validate a single event.
    
    Returns (is_valid, error_message).
    """
    # Check it's a dict
    if not isinstance(event, dict):
        return False, f"Event {event_index} is not a dict: {type(event)}"
    
    # Check required base fields
    if 'type' not in event:
        return False, f"Event {event_index} missing 'type' field"
    
    if 'ts' not in event:
        return False, f"Event {event_index} missing 'ts' field"
    
    event_type = event['type']
    
    # Type-specific validation
    if event_type == 'exec':
        required_fields = ['pid', 'ppid', 'comm', 'ts']
        for field in required_fields:
            if field not in event:
                return False, f"Exec event {event_index} missing '{field}'"
    
    elif event_type == 'open':
        required_fields = ['pid', 'fname', 'ts']
        for field in required_fields:
            if field not in event:
                return False, f"Open event {event_index} missing '{field}'"
    
    elif event_type == 'connect':
        required_fields = ['pid', 'ts']
        for field in required_fields:
            if field not in event:
                return False, f"Connect event {event_index} missing '{field}'"
    
    else:
        return False, f"Event {event_index} has unknown type: {event_type}"
    
    # Validate types
    if not isinstance(event['ts'], (int, float)):
        return False, f"Event {event_index} timestamp is not numeric: {type(event['ts'])}"
    
    if not isinstance(event.get('pid', 0), (int, float)):
        return False, f"Event {event_index} pid is not numeric"
    
    return True, None


def validate_jsonl_file(filepath):
    """
    Validate a JSONL file.
    
    Returns dict with validation results.
    """
    result = {
        'path': filepath,
        'name': Path(filepath).stem,
        'valid': False,
        'total_lines': 0,
        'valid_events': 0,
        'invalid_events': 0,
        'event_types': defaultdict(int),
        'timestamps_ordered': True,
        'first_timestamp': None,
        'last_timestamp': None,
        'errors': []
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            last_ts = None
            
            for line_num, line in enumerate(f, 1):
                result['total_lines'] += 1
                line = line.strip()
                
                if not line:
                    continue
                
                # Parse JSON
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as e:
                    result['invalid_events'] += 1
                    result['errors'].append(f"Line {line_num}: Invalid JSON: {e}")
                    continue
                
                # Validate event
                is_valid, error = validate_event(event, line_num)
                
                if not is_valid:
                    result['invalid_events'] += 1
                    result['errors'].append(error)
                    continue
                
                result['valid_events'] += 1
                result['event_types'][event['type']] += 1
                
                # Check timestamp ordering
                ts = event['ts']
                if result['first_timestamp'] is None:
                    result['first_timestamp'] = ts
                
                if last_ts is not None and ts < last_ts:
                    result['timestamps_ordered'] = False
                    result['errors'].append(f"Line {line_num}: Timestamp out of order ({ts} < {last_ts})")
                
                last_ts = ts
                result['last_timestamp'] = ts
        
        # Overall validity
        if result['valid_events'] > 0 and result['invalid_events'] == 0 and result['timestamps_ordered']:
            result['valid'] = True
    
    except Exception as e:
        result['errors'].append(f"Error reading file: {e}")
    
    return result


def main():
    """Main validation routine."""
    print("\n" + "="*80)
    print("QUT-DV25 Converted Dataset Validator")
    print("="*80)
    
    # Find converted files
    clean_files = glob.glob("data/qut_clean/*.jsonl")
    malicious_files = glob.glob("data/qut_malicious/*.jsonl")
    
    print(f"\nFound {len(clean_files)} clean files")
    print(f"Found {len(malicious_files)} malicious files")
    
    if len(clean_files) == 0 and len(malicious_files) == 0:
        print("\nERROR: No converted files found!")
        print("Run: python scripts/convert_qutdv25.py")
        sys.exit(1)
    
    all_files = clean_files + malicious_files
    
    # Validate each file
    print(f"\n{'='*80}")
    print("Validating files...")
    print('='*80)
    
    results = []
    for i, filepath in enumerate(all_files, 1):
        print(f"\n[{i}/{len(all_files)}] Validating {Path(filepath).name}...")
        
        result = validate_jsonl_file(filepath)
        results.append(result)
        
        if result['valid']:
            print(f"  ✓ VALID")
            print(f"    Events: {result['valid_events']}")
            print(f"    Types: {dict(result['event_types'])}")
        else:
            print(f"  ✗ INVALID")
            print(f"    Valid events: {result['valid_events']}")
            print(f"    Invalid events: {result['invalid_events']}")
            print(f"    Errors: {len(result['errors'])}")
            
            # Show first few errors
            for error in result['errors'][:3]:
                print(f"      - {error}")
            if len(result['errors']) > 3:
                print(f"      ... and {len(result['errors']) - 3} more")
    
    # Summary statistics
    print(f"\n{'='*80}")
    print("VALIDATION SUMMARY")
    print('='*80)
    
    valid_count = sum(1 for r in results if r['valid'])
    invalid_count = len(results) - valid_count
    
    total_events = sum(r['valid_events'] for r in results)
    total_invalid_events = sum(r['invalid_events'] for r in results)
    
    print(f"\nFiles:")
    print(f"  Total: {len(results)}")
    print(f"  Valid: {valid_count}")
    print(f"  Invalid: {invalid_count}")
    
    print(f"\nClean samples: {len(clean_files)} files")
    clean_valid = sum(1 for f in clean_files for r in results if r['path'] == f and r['valid'])
    print(f"  Valid: {clean_valid}")
    
    print(f"\nMalicious samples: {len(malicious_files)} files")
    mal_valid = sum(1 for f in malicious_files for r in results if r['path'] == f and r['valid'])
    print(f"  Valid: {mal_valid}")
    
    print(f"\nEvents:")
    print(f"  Total valid: {total_events:,}")
    print(f"  Total invalid: {total_invalid_events:,}")
    
    if valid_count > 0:
        avg_events = total_events / valid_count
        print(f"  Average events/file: {avg_events:.1f}")
        
        valid_results = [r for r in results if r['valid']]
        event_counts = [r['valid_events'] for r in valid_results]
        
        print(f"  Min events: {min(event_counts):,}")
        print(f"  Max events: {max(event_counts):,}")
    
    # Event type distribution
    all_event_types = defaultdict(int)
    for r in results:
        for event_type, count in r['event_types'].items():
            all_event_types[event_type] += count
    
    print(f"\nEvent type distribution:")
    for event_type, count in sorted(all_event_types.items()):
        pct = 100 * count / total_events if total_events > 0 else 0
        print(f"  {event_type}: {count:,} ({pct:.1f}%)")
    
    # Timestamp ordering check
    unordered_count = sum(1 for r in results if not r['timestamps_ordered'])
    if unordered_count > 0:
        print(f"\n⚠️  WARNING: {unordered_count} files have timestamp ordering issues")
    
    # List invalid files
    invalid_files = [r for r in results if not r['valid']]
    if invalid_files:
        print(f"\nInvalid files ({len(invalid_files)}):")
        for r in invalid_files[:10]:  # Show first 10
            print(f"  - {r['name']}: {len(r['errors'])} errors")
        if len(invalid_files) > 10:
            print(f"  ... and {len(invalid_files) - 10} more")
    
    # Overall verdict
    print(f"\n{'='*80}")
    
    if invalid_count == 0:
        print("✅ PASS: All files are valid")
        print("\nDataset ready for training!")
        print("\nNext steps:")
        print("1. Test pipeline: python scripts/test_qutdv25_pipeline.py")
        print("2. Train model: sudo make train-split")
    else:
        success_rate = valid_count / len(results)
        print(f"⚠️  PARTIAL: {invalid_count} files failed validation")
        print(f"\nSuccess rate: {valid_count}/{len(results)} ({100*success_rate:.1f}%)")
        
        if success_rate >= 0.95:
            print("\n✓ Success rate >= 95% - acceptable for training")
            print("  (Some samples may have format issues but most data is usable)")
            print("\nYou can proceed to training:")
            print("  sudo make train-split")
        elif success_rate >= 0.90:
            print("\n~ Success rate >= 90% - usable but review failures")
            print("  Consider investigating invalid samples")
        else:
            print("\n✗ Success rate < 90% - review failures before training")
            print("  Re-run conversion or investigate data issues")
    
    print("="*80 + "\n")
    
    return 0 if invalid_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
