"""
Extract a subset of packages from full QUT-DV25 dataset.

This script selects N packages from the full dataset while maintaining
class balance (50% benign, 50% malicious).

Usage:
    python3 scripts/extract_qutdv25_subset.py --input QUT-DV25_Full --count 2500 --output QUT-DV25_Datasets
"""

import os
import sys
import argparse
import shutil
import random
from pathlib import Path
from collections import defaultdict


def discover_samples(raw_dataset_dir, trace_type='Opensnoop'):
    """
    Discover all available samples in the dataset.
    
    Args:
        raw_dataset_dir: Path to QUT-DV_Raw_Datasets directory
        trace_type: Type of trace to check (Opensnoop, Installation, etc.)
    
    Returns:
        dict with 'benign' and 'malicious' lists of sample names
    """
    samples = {
        'benign': [],
        'malicious': []
    }
    
    # Benign samples
    benign_dir = Path(raw_dataset_dir) / "QUT-DV25_Benign_Raw_Data_Samples" / f"QUT-DV25_{trace_type}_Traces"
    if benign_dir.exists():
        files = [f for f in os.listdir(benign_dir) if f.endswith('_trace.txt') and not f.startswith('._')]
        # Extract package names (remove _TYPE_trace.txt suffix)
        samples['benign'] = [f.replace(f'_{trace_type.lower()}_trace.txt', '') for f in files]
    
    # Malicious samples
    malicious_dir = Path(raw_dataset_dir) / "QUT-DV25_Malicious_Raw_Data_Samples" / f"QUT-DV25_{trace_type}_Traces"
    if malicious_dir.exists():
        files = [f for f in os.listdir(malicious_dir) if f.endswith('_trace.txt') and not f.startswith('._')]
        samples['malicious'] = [f.replace(f'_{trace_type.lower()}_trace.txt', '') for f in files]
    
    return samples


def select_subset(all_samples, target_count, seed=42):
    """
    Select a balanced subset of samples.
    
    Args:
        all_samples: dict with 'benign' and 'malicious' lists
        target_count: Total number of samples to select
        seed: Random seed for reproducibility
    
    Returns:
        dict with selected 'benign' and 'malicious' samples
    """
    random.seed(seed)
    
    # Target counts (50/50 split)
    target_benign = target_count // 2
    target_malicious = target_count - target_benign
    
    # Available counts
    available_benign = len(all_samples['benign'])
    available_malicious = len(all_samples['malicious'])
    
    print(f"\nSample availability:")
    print(f"  Benign: {available_benign} available, need {target_benign}")
    print(f"  Malicious: {available_malicious} available, need {target_malicious}")
    
    # Check if we have enough samples
    if available_benign < target_benign:
        print(f"  ⚠️  Warning: Not enough benign samples, using all {available_benign}")
        target_benign = available_benign
    
    if available_malicious < target_malicious:
        print(f"  ⚠️  Warning: Not enough malicious samples, using all {available_malicious}")
        target_malicious = available_malicious
    
    # Random selection
    selected = {
        'benign': random.sample(all_samples['benign'], target_benign),
        'malicious': random.sample(all_samples['malicious'], target_malicious)
    }
    
    actual_count = len(selected['benign']) + len(selected['malicious'])
    print(f"\nSelected {actual_count} samples ({len(selected['benign'])} benign, {len(selected['malicious'])} malicious)")
    
    return selected


def copy_sample_files(sample_name, label, source_dir, dest_dir, trace_types):
    """
    Copy all trace files for a sample.
    
    Args:
        sample_name: Name of the package
        label: 'benign' or 'malicious'
        source_dir: Source QUT-DV_Raw_Datasets directory
        dest_dir: Destination directory
        trace_types: List of trace types to copy
    
    Returns:
        Number of files successfully copied
    """
    if label == 'benign':
        source_label_dir = 'QUT-DV25_Benign_Raw_Data_Samples'
    else:
        source_label_dir = 'QUT-DV25_Malicious_Raw_Data_Samples'
    
    files_copied = 0
    
    for trace_type in trace_types:
        # Construct source and destination paths
        source_trace_dir = Path(source_dir) / source_label_dir / f"QUT-DV25_{trace_type}_Traces"
        dest_trace_dir = Path(dest_dir) / source_label_dir / f"QUT-DV25_{trace_type}_Traces"
        
        # Create destination directory
        dest_trace_dir.mkdir(parents=True, exist_ok=True)
        
        # Determine file pattern based on trace type
        if trace_type == "PIDs":
            source_file = source_trace_dir / f"traced_pids_{sample_name}.txt"
        else:
            source_file = source_trace_dir / f"{sample_name}_{trace_type.lower()}_trace.txt"
        
        # Copy file if it exists
        if source_file.exists():
            dest_file = dest_trace_dir / source_file.name
            shutil.copy2(source_file, dest_file)
            files_copied += 1
    
    return files_copied


def extract_subset(input_dir, output_dir, target_count=2500, seed=42):
    """
    Extract a subset of samples from full dataset.
    
    Args:
        input_dir: Path to full QUT-DV25 dataset
        output_dir: Path to output subset
        target_count: Number of samples to extract
        seed: Random seed
    """
    print("\n" + "="*80)
    print(f"Extracting {target_count} samples from QUT-DV25 dataset")
    print("="*80)
    
    raw_dataset_dir = Path(input_dir) / "QUT-DV_Raw_Datasets"
    
    if not raw_dataset_dir.exists():
        print(f"\nERROR: Input directory not found: {raw_dataset_dir}")
        print("Expected structure: INPUT_DIR/QUT-DV_Raw_Datasets/")
        return False
    
    # Discover all available samples
    print("\nDiscovering available samples...")
    all_samples = discover_samples(raw_dataset_dir)
    
    total_available = len(all_samples['benign']) + len(all_samples['malicious'])
    print(f"Found {total_available} samples:")
    print(f"  Benign: {len(all_samples['benign'])}")
    print(f"  Malicious: {len(all_samples['malicious'])}")
    
    if total_available == 0:
        print("\nERROR: No samples found in dataset!")
        return False
    
    # Select subset
    selected_samples = select_subset(all_samples, target_count, seed)
    
    # Copy files
    print(f"\nCopying files to: {output_dir}")
    
    trace_types = ['Opensnoop', 'PIDs', 'Installation', 'Filetop', 'TCP', 'Pattern']
    
    total_files = 0
    failed = 0
    
    for label in ['benign', 'malicious']:
        print(f"\nCopying {label} samples...")
        
        for i, sample_name in enumerate(selected_samples[label], 1):
            files_copied = copy_sample_files(
                sample_name, label,
                raw_dataset_dir,
                Path(output_dir) / "QUT-DV_Raw_Datasets",
                trace_types
            )
            
            if files_copied > 0:
                total_files += files_copied
                if i % 100 == 0:
                    print(f"  [{i}/{len(selected_samples[label])}] Copied {sample_name}")
            else:
                failed += 1
                print(f"  WARNING: No files found for {sample_name}")
    
    # Summary
    print("\n" + "="*80)
    print("EXTRACTION SUMMARY")
    print("="*80)
    
    actual_samples = len(selected_samples['benign']) + len(selected_samples['malicious'])
    print(f"\nSamples extracted: {actual_samples}")
    print(f"  Benign: {len(selected_samples['benign'])}")
    print(f"  Malicious: {len(selected_samples['malicious'])}")
    print(f"\nFiles copied: {total_files}")
    print(f"Failed samples: {failed}")
    
    print(f"\nOutput location: {output_dir}")
    print(f"\nNext step: python3 scripts/convert_qutdv25.py --input {output_dir}/QUT-DV_Raw_Datasets")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Extract subset from QUT-DV25 full dataset',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Extract 2500 samples (1250 benign + 1250 malicious)
    python3 scripts/extract_qutdv25_subset.py \\
        --input QUT-DV25_Full \\
        --output QUT-DV25_Datasets \\
        --count 2500
    
    # Extract 1000 samples with custom seed
    python3 scripts/extract_qutdv25_subset.py \\
        --input QUT-DV25_Full \\
        --count 1000 \\
        --seed 123

Note:
    - Maintains 50/50 benign/malicious balance
    - Copies all trace types (Opensnoop, PIDs, Installation, etc.)
    - Uses random sampling with fixed seed for reproducibility
        '''
    )
    
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Path to full QUT-DV25 dataset'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='QUT-DV25_Datasets',
        help='Output directory for subset (default: QUT-DV25_Datasets)'
    )
    
    parser.add_argument(
        '--count',
        type=int,
        default=2500,
        help='Number of samples to extract (default: 2500)'
    )
    
    parser.add_argument(
        '--seed',
        type=int,
        default=42,
        help='Random seed for reproducibility (default: 42)'
    )
    
    args = parser.parse_args()
    
    # Extract subset
    success = extract_subset(
        args.input,
        args.output,
        args.count,
        args.seed
    )
    
    if success:
        print("\n✅ Subset extraction complete!")
        print("\nReady to convert to SCBF format.")
    else:
        print("\n❌ Subset extraction failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
