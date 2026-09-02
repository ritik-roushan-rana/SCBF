#!/usr/bin/env python3
"""
SCBF Setup Verification Script

Checks that all dependencies, files, and permissions are correctly configured.
Run this before attempting to collect data or train models.
"""

import sys
import os
import subprocess
import platform
from pathlib import Path

CHECKS_PASSED = []
CHECKS_FAILED = []

def check(name, condition, error_msg="", fix_hint=""):
    """Record a check result."""
    if condition:
        CHECKS_PASSED.append(name)
        print(f"✓ {name}")
        return True
    else:
        CHECKS_FAILED.append((name, error_msg, fix_hint))
        print(f"✗ {name}")
        if error_msg:
            print(f"  Error: {error_msg}")
        if fix_hint:
            print(f"  Fix: {fix_hint}")
        return False

def main():
    print("=" * 60)
    print("SCBF Setup Verification")
    print("=" * 60)
    print()

    # 1. Platform check
    print("[1/10] Checking platform...")
    is_linux = platform.system() == "Linux"
    check(
        "Linux OS",
        is_linux,
        f"Running on {platform.system()}, but SCBF requires Linux",
        "Run on a Linux machine or VM (Ubuntu 20.04+ recommended)"
    )
    print()

    # 2. Python version
    print("[2/10] Checking Python version...")
    py_version = sys.version_info
    check(
        "Python 3.11+",
        py_version >= (3, 11),
        f"Python {py_version.major}.{py_version.minor} found, need 3.11+",
        "Install Python 3.11 or newer: apt install python3.11"
    )
    print()

    # 3. Root/sudo access
    print("[3/10] Checking permissions...")
    is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    check(
        "Root/sudo access",
        is_root,
        "Not running as root (eBPF requires root)",
        "Run with sudo: sudo python3 verify_setup.py"
    )
    print()

    # 4. BCC availability
    print("[4/10] Checking BCC...")
    try:
        from bcc import BPF
        bcc_ok = True
    except ImportError:
        bcc_ok = False
    
    check(
        "BCC (BPF Compiler Collection)",
        bcc_ok,
        "Cannot import bcc module",
        "Install: sudo apt install bpfcc-tools python3-bpfcc"
    )
    print()

    # 5. Kernel headers
    print("[5/10] Checking kernel headers...")
    kernel_ver = platform.release()
    headers_path = f"/lib/modules/{kernel_ver}/build"
    headers_exist = os.path.exists(headers_path)
    check(
        f"Kernel headers ({kernel_ver})",
        headers_exist,
        f"Headers not found at {headers_path}",
        f"Install: sudo apt install linux-headers-{kernel_ver}"
    )
    print()

    # 6. PyTorch
    print("[6/10] Checking PyTorch...")
    try:
        import torch
        torch_ok = True
    except ImportError:
        torch_ok = False
    
    check(
        "PyTorch",
        torch_ok,
        "Cannot import torch",
        "Install: pip install torch"
    )
    print()

    # 7. NumPy
    print("[7/10] Checking NumPy...")
    try:
        import numpy
        numpy_ok = True
    except ImportError:
        numpy_ok = False
    
    check(
        "NumPy",
        numpy_ok,
        "Cannot import numpy",
        "Install: pip install numpy"
    )
    print()

    # 8. Directory structure
    print("[8/10] Checking project structure...")
    required_dirs = [
        "scbf/capture",
        "scbf/models",
        "scbf/training",
        "scbf/detection",
        "scripts",
        "tests",
        "data/clean",
        "data/malicious",
        "models",
        "docs"
    ]
    
    missing_dirs = [d for d in required_dirs if not os.path.isdir(d)]
    check(
        "Project directories",
        len(missing_dirs) == 0,
        f"Missing directories: {', '.join(missing_dirs)}",
        "Re-run project structure setup"
    )
    print()

    # 9. Core Python files
    print("[9/10] Checking core files...")
    required_files = [
        "scbf/capture/install_monitor.py",
        "scbf/models/tgn_encoder.py",
        "scbf/models/itbg_constructor.py",
        "scbf/training/train.py",
        "scbf/training/build_envelope.py",
        "scbf/detection/cli.py",
        "scripts/collect_clean_data.py",
        "scripts/collect_malicious_data.py"
    ]
    
    missing_files = [f for f in required_files if not os.path.isfile(f)]
    check(
        "Core Python files",
        len(missing_files) == 0,
        f"Missing files: {', '.join(missing_files)}",
        "Copy files from old structure or re-clone repo"
    )
    print()

    # 10. Import test
    print("[10/10] Testing imports...")
    try:
        sys.path.insert(0, os.getcwd())
        from scbf.models.tgn_encoder import TGNEncoder
        from scbf.models.itbg_constructor import ITBGConstructor
        from scbf.capture.install_monitor import InstallMonitor
        import_ok = True
    except Exception as e:
        import_ok = False
        import_error = str(e)
    
    check(
        "SCBF imports",
        import_ok,
        f"Import failed: {import_error if not import_ok else ''}",
        "Ensure __init__.py files exist and paths are correct"
    )
    print()

    # Summary
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"✓ Passed: {len(CHECKS_PASSED)}/10")
    print(f"✗ Failed: {len(CHECKS_FAILED)}/10")
    print()

    if CHECKS_FAILED:
        print("Failed checks:")
        for name, error, fix in CHECKS_FAILED:
            print(f"  • {name}")
            if error:
                print(f"    {error}")
            if fix:
                print(f"    → {fix}")
        print()
        print("Fix the above issues before proceeding.")
        return 1
    else:
        print("✓ All checks passed! Ready to:")
        print("  1. Collect data:  sudo python scripts/collect_clean_data.py")
        print("  2. Train model:   sudo python -m scbf.training.train")
        print("  3. Scan packages: sudo python -m scbf.detection.cli --package <name>")
        print()
        print("Or use Makefile:")
        print("  sudo make collect-data")
        print("  sudo make train")
        print("  sudo make scan PKG=requests")
        return 0

if __name__ == "__main__":
    sys.exit(main())
