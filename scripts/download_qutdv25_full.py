"""
Download full QUT-DV25 dataset and extract 2500 samples.

This script downloads the complete QUT-DV25 dataset from GitHub/Zenodo
and extracts a subset of 2500 packages for training.

Usage:
    python3 scripts/download_qutdv25_full.py --count 2500
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path


def download_full_dataset(output_dir, method='git-lfs'):
    """
    Download the full QUT-DV25 dataset.
    
    The dataset is hosted on GitHub with Git LFS for large files.
    Total size: ~450 GB (full dataset with all traces)
    
    Args:
        output_dir: Directory to download dataset
        method: 'git-lfs' or 'zenodo' or 'manual'
    """
    print("\n" + "="*80)
    print("QUT-DV25 Full Dataset Downloader")
    print("="*80)
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if method == 'git-lfs':
        print("\nMethod: Git LFS Clone")
        print("⚠️  WARNING: This will download ~450 GB of data!")
        print("   Make sure you have:")
        print("   - Git LFS installed: brew install git-lfs")
        print("   - Enough disk space: 500+ GB free")
        print("   - Fast internet connection")
        
        response = input("\nProceed with download? (yes/no): ")
        if response.lower() != 'yes':
            print("Download cancelled.")
            return False
        
        repo_url = "https://github.com/tanzirmehedi/QUT-DV25.git"
        
        print(f"\nCloning repository to: {output_dir}")
        print("This may take several hours depending on your connection...")
        
        try:
            # Initialize git lfs
            subprocess.run(['git', 'lfs', 'install'], check=True)
            
            # Clone the repository
            subprocess.run([
                'git', 'clone', '--depth', '1',
                repo_url,
                str(output_dir)
            ], check=True)
            
            print("\n✓ Download complete!")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"\n✗ Error during download: {e}")
            return False
        
    elif method == 'zenodo':
        print("\nMethod: Zenodo Direct Download")
        print("Dataset DOI: Check https://github.com/tanzirmehedi/QUT-DV25 for links")
        print("\nPlease download manually from Zenodo and extract to:")
        print(f"  {output_dir}")
        return False
    
    elif method == 'manual':
        print("\nMethod: Manual Download")
        print("\nInstructions:")
        print("1. Visit: https://github.com/tanzirmehedi/QUT-DV25")
        print("2. Check README for download links (Zenodo, Google Drive, etc.)")
        print("3. Download the 'Raw_Datasets' folder")
        print("4. Extract to:")
        print(f"   {output_dir}")
        return False


def check_dataset_structure(dataset_dir):
    """Check if downloaded dataset has correct structure."""
    dataset_dir = Path(dataset_dir)
    
    required_dirs = [
        'QUT-DV_Raw_Datasets/QUT-DV25_Benign_Raw_Data_Samples',
        'QUT-DV_Raw_Datasets/QUT-DV25_Malicious_Raw_Data_Samples'
    ]
    
    for dir_path in required_dirs:
        full_path = dataset_dir / dir_path
        if not full_path.exists():
            print(f"✗ Missing: {full_path}")
            return False
    
    print("✓ Dataset structure verified")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Download QUT-DV25 full dataset',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Download full dataset via Git LFS (~450 GB)
    python3 scripts/download_qutdv25_full.py --output QUT-DV25_Full
    
    # Get manual download instructions
    python3 scripts/download_qutdv25_full.py --method manual
    
Note:
    The full QUT-DV25 dataset is VERY LARGE (~450 GB).
    
    Alternative approach:
    1. Check GitHub README for Google Drive / Zenodo links
    2. Download specific trace types you need
    3. Use --method manual to get instructions
        '''
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='QUT-DV25_Full_Dataset',
        help='Output directory for dataset (default: QUT-DV25_Full_Dataset)'
    )
    
    parser.add_argument(
        '--method',
        type=str,
        choices=['git-lfs', 'zenodo', 'manual'],
        default='manual',
        help='Download method (default: manual for instructions)'
    )
    
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("QUT-DV25 Full Dataset Download")
    print("="*80)
    
    print(f"\nDataset: https://github.com/tanzirmehedi/QUT-DV25")
    print(f"Total packages: 14,271 (7,144 benign + 7,127 malicious)")
    print(f"Estimated size: ~450 GB (all traces)")
    
    # Download dataset
    success = download_full_dataset(args.output, args.method)
    
    if success:
        # Verify structure
        check_dataset_structure(args.output)
        
        print("\n" + "="*80)
        print("Next Steps:")
        print("="*80)
        print(f"\n1. Verify dataset downloaded to: {args.output}")
        print(f"2. Extract subset:")
        print(f"   python3 scripts/extract_qutdv25_subset.py --input {args.output} --count 2500")
        print(f"3. Convert to SCBF format:")
        print(f"   python3 scripts/convert_qutdv25.py")
    else:
        print("\n" + "="*80)
        print("Manual Download Recommended")
        print("="*80)
        print("\nDue to the large dataset size, manual download is recommended:")
        print("\n1. Visit: https://github.com/tanzirmehedi/QUT-DV25")
        print("2. Check README for download options:")
        print("   - Zenodo DOI link")
        print("   - Google Drive link (if available)")
        print("   - Hugging Face dataset (if available)")
        print("\n3. Download specific components you need:")
        print("   - Opensnoop traces (file operations)")
        print("   - PID traces")
        print("   - Installation traces")
        print("\n4. Extract to: QUT-DV25_Full_Dataset/")
        print("\n5. Then run:")
        print("   python3 scripts/extract_qutdv25_subset.py --count 2500")


if __name__ == "__main__":
    main()
