"""
Aggregate per-package JSONL files into Zenodo dataset structure.

This script:
1. Reads per-package trace files from data/clean/ and data/malicious/
2. Merges them into aggregated event-level JSONL files
3. Writes to data/zenodo_13746167/{benign,malware}/data/
4. Copies individual traces to data/zenodo_13746167/{benign,malware}/traces/

Usage:
    python scripts/aggregate_jsonl.py
"""

import json
import shutil
from pathlib import Path
from collections import defaultdict


def sanitize_filename(package_name, version="unknown"):
    """
    Create safe filename from package name and version.
    
    Replaces problematic characters:
    - / → -
    - spaces → -
    - special chars → -
    """
    safe_package = package_name.replace("/", "-").replace(" ", "-")
    safe_version = version.replace("/", "-").replace(" ", "-")
    
    # Remove any remaining problematic characters
    safe_package = "".join(c if c.isalnum() or c in ".-_" else "-" for c in safe_package)
    safe_version = "".join(c if c.isalnum() or c in ".-_" else "-" for c in safe_version)
    
    return f"{safe_package}-{safe_version}.jsonl"


def extract_package_info(events):
    """Extract package metadata from events."""
    for event in events:
        if "package" in event:
            return {
                "package": event.get("package", "unknown"),
                "version": event.get("version", "unknown"),
                "artifact": event.get("artifact", "unknown"),
            }
    return {"package": "unknown", "version": "unknown", "artifact": "unknown"}


def aggregate_dataset(source_dir, target_data_dir, target_traces_dir, label):
    """
    Aggregate per-package JSONL files into Zenodo structure.
    
    Args:
        source_dir: Directory with per-package JSONL files (e.g., data/clean/)
        target_data_dir: Output directory for aggregated JSONL (e.g., data/zenodo_13746167/benign/data/)
        target_traces_dir: Output directory for individual traces (e.g., data/zenodo_13746167/benign/traces/)
        label: Label to add to events ("benign" or "malicious")
    
    Returns:
        dict with statistics
    """
    source_path = Path(source_dir)
    target_data_path = Path(target_data_dir)
    target_traces_path = Path(target_traces_dir)
    
    # Create output directories
    target_data_path.mkdir(parents=True, exist_ok=True)
    target_traces_path.mkdir(parents=True, exist_ok=True)
    
    # Output files
    aggregated_file = target_data_path / f"{label}.jsonl"
    
    # Statistics
    stats = {
        "source_files": 0,
        "processed_files": 0,
        "skipped_files": 0,
        "total_events": 0,
        "packages": set(),
        "errors": []
    }
    
    # Process each source file
    source_files = sorted(source_path.glob("*.jsonl"))
    stats["source_files"] = len(source_files)
    
    print(f"\nProcessing {label} dataset...")
    print(f"Source: {source_dir}")
    print(f"Found {len(source_files)} files")
    
    with open(aggregated_file, 'w', encoding='utf-8') as agg_f:
        for source_file in source_files:
            try:
                # Read events
                events = []
                with open(source_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        event = json.loads(line)
                        
                        # Add label if not present
                        if "label" not in event:
                            event["label"] = label
                        
                        events.append(event)
                
                if not events:
                    print(f"  ⚠️  {source_file.name}: Empty file, skipping")
                    stats["skipped_files"] += 1
                    continue
                
                # Extract package info
                pkg_info = extract_package_info(events)
                pkg_name = pkg_info["package"]
                pkg_version = pkg_info["version"]
                
                # Create trace filename
                trace_filename = sanitize_filename(pkg_name, pkg_version)
                trace_file = target_traces_path / trace_filename
                
                # Write individual trace
                with open(trace_file, 'w', encoding='utf-8') as trace_f:
                    for event in events:
                        trace_f.write(json.dumps(event) + '\n')
                
                # Append to aggregated file
                for event in events:
                    agg_f.write(json.dumps(event) + '\n')
                
                # Update stats
                stats["processed_files"] += 1
                stats["total_events"] += len(events)
                stats["packages"].add(f"{pkg_name}-{pkg_version}")
                
                print(f"  ✓ {source_file.name}: {len(events)} events → {trace_filename}")
            
            except json.JSONDecodeError as e:
                error_msg = f"{source_file.name}: Invalid JSON - {e}"
                print(f"  ✗ {error_msg}")
                stats["errors"].append(error_msg)
                stats["skipped_files"] += 1
            
            except Exception as e:
                error_msg = f"{source_file.name}: {e}"
                print(f"  ✗ {error_msg}")
                stats["errors"].append(error_msg)
                stats["skipped_files"] += 1
    
    # Convert set to count
    stats["unique_packages"] = len(stats["packages"])
    stats["packages"] = list(stats["packages"])
    
    return stats


def print_summary(benign_stats, malware_stats):
    """Print aggregation summary."""
    print("\n" + "="*80)
    print("AGGREGATION SUMMARY")
    print("="*80)
    
    print("\n📦 Benign Dataset")
    print(f"  Source files: {benign_stats['source_files']}")
    print(f"  Processed: {benign_stats['processed_files']}")
    print(f"  Skipped: {benign_stats['skipped_files']}")
    print(f"  Unique packages: {benign_stats['unique_packages']}")
    print(f"  Total events: {benign_stats['total_events']:,}")
    if benign_stats['processed_files'] > 0:
        avg = benign_stats['total_events'] / benign_stats['processed_files']
        print(f"  Avg events/package: {avg:.1f}")
    
    print("\n🦠 Malware Dataset")
    print(f"  Source files: {malware_stats['source_files']}")
    print(f"  Processed: {malware_stats['processed_files']}")
    print(f"  Skipped: {malware_stats['skipped_files']}")
    print(f"  Unique packages: {malware_stats['unique_packages']}")
    print(f"  Total events: {malware_stats['total_events']:,}")
    if malware_stats['processed_files'] > 0:
        avg = malware_stats['total_events'] / malware_stats['processed_files']
        print(f"  Avg events/package: {avg:.1f}")
    
    print("\n📊 Combined Statistics")
    total_packages = benign_stats['processed_files'] + malware_stats['processed_files']
    total_events = benign_stats['total_events'] + malware_stats['total_events']
    print(f"  Total packages: {total_packages}")
    print(f"  Total events: {total_events:,}")
    
    # Print errors
    all_errors = benign_stats['errors'] + malware_stats['errors']
    if all_errors:
        print(f"\n⚠️  Errors ({len(all_errors)}):")
        for error in all_errors[:10]:
            print(f"  - {error}")
        if len(all_errors) > 10:
            print(f"  ... and {len(all_errors) - 10} more")
    
    print("\n✅ Output files:")
    print("  data/zenodo_13746167/benign/data/benign.jsonl")
    print("  data/zenodo_13746167/benign/traces/*.jsonl")
    print("  data/zenodo_13746167/malware/data/malware.jsonl")
    print("  data/zenodo_13746167/malware/traces/*.jsonl")
    
    print("\n📝 Next steps:")
    print("  1. Validate: python scripts/validate_dataset.py")
    print("  2. Train: sudo make train-split")
    
    print("\n" + "="*80)


def main():
    """Main aggregation workflow."""
    print("="*80)
    print("SCBF Dataset Aggregation")
    print("="*80)
    
    # Check if source directories exist
    clean_dir = Path("data/clean")
    malicious_dir = Path("data/malicious")
    
    if not clean_dir.exists():
        print(f"\n❌ ERROR: {clean_dir} does not exist")
        print("Run data collection first:")
        print("  sudo python scripts/collect_clean_data.py")
        return
    
    if not malicious_dir.exists():
        print(f"\n❌ ERROR: {malicious_dir} does not exist")
        print("Run data collection first:")
        print("  sudo python scripts/collect_malicious_data.py")
        return
    
    # Aggregate benign dataset
    benign_stats = aggregate_dataset(
        source_dir="data/clean",
        target_data_dir="data/zenodo_13746167/benign/data",
        target_traces_dir="data/zenodo_13746167/benign/traces",
        label="benign"
    )
    
    # Aggregate malware dataset
    malware_stats = aggregate_dataset(
        source_dir="data/malicious",
        target_data_dir="data/zenodo_13746167/malware/data",
        target_traces_dir="data/zenodo_13746167/malware/traces",
        label="malicious"
    )
    
    # Print summary
    print_summary(benign_stats, malware_stats)


if __name__ == "__main__":
    main()
