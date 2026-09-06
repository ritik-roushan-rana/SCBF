"""
SCBF Detection CLI

Scans packages using the trained hybrid model and behavioral envelope.

Two modes:
1. **File mode**: Scan an existing trace file (works on macOS)
2. **Live mode**: Run pip install with monitoring (Linux only, requires eBPF)

Usage:
    # Scan existing trace file
    python -m scbf.detection.cli --trace path/to/trace.jsonl
    
    # Scan a package by name (Linux only)
    python -m scbf.detection.cli --package requests
    
    # Batch scan all traces in a directory
    python -m scbf.detection.cli --batch data/zenodo_13746167/malware/traces/
"""

import argparse
import os
import sys
import json
import glob
import shutil
import subprocess
import platform
import torch
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from training.train_hybrid_v2 import HybridClassifierV2, load_events


def load_model(model_path="models/scbf_hybrid_v2.pt", num_nodes=50000):
    """Load the trained hybrid model."""
    if not os.path.exists(model_path):
        print(f"❌ Model not found: {model_path}")
        print("Please train the model first: make train-hybrid-v2")
        sys.exit(1)
    
    model = HybridClassifierV2(num_nodes=num_nodes)
    model.load_state_dict(torch.load(model_path))
    model.eval()
    return model


def load_envelope(envelope_path="models/envelope_v2.npy",
                  info_path="models/envelope_v2_info.json"):
    """Load the behavioral envelope."""
    if not os.path.exists(envelope_path):
        print(f"❌ Envelope not found: {envelope_path}")
        print("Please build envelope first: make build-envelope")
        sys.exit(1)
    
    centroid = np.load(envelope_path)
    
    threshold = None
    mean_dist = None
    std_dist = None
    
    if os.path.exists(info_path):
        with open(info_path, 'r') as f:
            info = json.load(f)
            threshold = info.get('threshold')
            mean_dist = info.get('mean_distance')
            std_dist = info.get('std_distance')
    
    return centroid, threshold, mean_dist, std_dist


def compute_verdict(distance, threshold, mean_dist, std_dist):
    """
    Compute verdict based on distance from clean centroid.
    
    Uses graduated scoring:
    - BLOCK: distance > threshold (mean + 2.5*std)
    - WARN:  distance > mean + 1.5*std
    - ALLOW: distance <= mean + 1.5*std
    """
    warn_threshold = mean_dist + 1.5 * std_dist if mean_dist and std_dist else threshold * 0.7
    
    # Threat score 0-100
    if distance <= mean_dist:
        threat_score = 0
    elif distance >= threshold:
        threat_score = min(100, 75 + int((distance - threshold) / max(0.1, std_dist) * 10))
    else:
        # Linear scale between mean and threshold
        progress = (distance - mean_dist) / max(0.001, (threshold - mean_dist))
        threat_score = int(75 * progress)
    
    if distance >= threshold:
        verdict = "BLOCK"
        emoji = "🚫"
    elif distance >= warn_threshold:
        verdict = "WARN"
        emoji = "⚠️"
    else:
        verdict = "ALLOW"
        emoji = "✅"
    
    return verdict, threat_score, emoji


def scan_trace_file(trace_path, model=None, envelope_data=None, verbose=True):
    """Scan a single trace file."""
    if model is None:
        model = load_model()
    
    if envelope_data is None:
        centroid, threshold, mean_dist, std_dist = load_envelope()
    else:
        centroid, threshold, mean_dist, std_dist = envelope_data
    
    # Load events
    try:
        events = load_events(trace_path)
    except Exception as e:
        print(f"❌ Error loading trace: {e}")
        return None
    
    if len(events) == 0:
        print(f"⚠️  Empty trace file")
        return None
    
    # Extract DNA vector using hybrid model
    with torch.no_grad():
        combined_vector, logits = model(events)
    
    if combined_vector is None:
        print(f"❌ Failed to extract features")
        return None
    
    # Compute distance to envelope
    dna_np = combined_vector.cpu().numpy()
    distance = float(np.linalg.norm(dna_np - centroid))
    
    # Compute classifier probability (bonus info)
    classifier_prob = float(torch.sigmoid(logits).item()) if logits is not None else None
    
    # Compute verdict
    verdict, threat_score, emoji = compute_verdict(distance, threshold, mean_dist, std_dist)
    
    if verbose:
        package_name = os.path.basename(trace_path).replace('.jsonl', '').replace('.tar.gz', '')
        print(f"\n{'=' * 80}")
        print(f"{emoji}  SCBF SCAN REPORT")
        print(f"{'=' * 80}")
        print(f"Package:            {package_name}")
        print(f"Events analyzed:    {len(events)}")
        print(f"Distance to clean:  {distance:.4f}")
        print(f"Clean threshold:    {threshold:.4f} (mean + 2.5*std)")
        print(f"Threat score:       {threat_score}/100")
        if classifier_prob is not None:
            print(f"Classifier prob:    {classifier_prob:.4f}")
        print(f"\n{'─' * 80}")
        print(f"VERDICT: {emoji}  {verdict}")
        print(f"{'─' * 80}")
        
        if verdict == "BLOCK":
            print(f"⛔ Package appears MALICIOUS - do NOT install")
        elif verdict == "WARN":
            print(f"⚠️  Package shows suspicious behavior - review carefully")
        else:
            print(f"✓ Package appears clean")
        print(f"{'=' * 80}")
    
    return {
        'package': os.path.basename(trace_path),
        'events': len(events),
        'distance': distance,
        'threshold': threshold,
        'threat_score': threat_score,
        'classifier_prob': classifier_prob,
        'verdict': verdict,
    }


def batch_scan(directory, model=None, envelope_data=None):
    """Scan all trace files in a directory."""
    if model is None:
        model = load_model()
    
    if envelope_data is None:
        centroid, threshold, mean_dist, std_dist = load_envelope()
        envelope_data = (centroid, threshold, mean_dist, std_dist)
    
    trace_files = glob.glob(os.path.join(directory, "*.jsonl"))
    print(f"Found {len(trace_files)} trace files to scan\n")
    
    results = []
    counts = {'BLOCK': 0, 'WARN': 0, 'ALLOW': 0, 'ERROR': 0}
    
    for i, trace_path in enumerate(trace_files):
        if (i + 1) % 25 == 0:
            print(f"Progress: {i + 1}/{len(trace_files)}")
        
        result = scan_trace_file(trace_path, model, envelope_data, verbose=False)
        
        if result:
            results.append(result)
            counts[result['verdict']] += 1
        else:
            counts['ERROR'] += 1
    
    # Summary
    print("\n" + "=" * 80)
    print("BATCH SCAN SUMMARY")
    print("=" * 80)
    print(f"Total scanned:  {len(trace_files)}")
    print(f"🚫 BLOCK:       {counts['BLOCK']:4d}  ({counts['BLOCK']/max(1,len(trace_files)):.1%})")
    print(f"⚠️  WARN:        {counts['WARN']:4d}  ({counts['WARN']/max(1,len(trace_files)):.1%})")
    print(f"✅ ALLOW:       {counts['ALLOW']:4d}  ({counts['ALLOW']/max(1,len(trace_files)):.1%})")
    if counts['ERROR']:
        print(f"❌ ERROR:       {counts['ERROR']:4d}")
    
    # Show top threats
    blocked = [r for r in results if r['verdict'] == 'BLOCK']
    if blocked:
        blocked.sort(key=lambda x: -x['threat_score'])
        print(f"\nTop {min(10, len(blocked))} highest-threat packages:")
        for r in blocked[:10]:
            print(f"  {r['threat_score']:3d}/100  distance={r['distance']:.3f}  {r['package']}")
    
    return results


def scan_package_live(pkg_name, target_dir="/tmp/scbf_sandbox"):
    """
    Live scan by running pip install and capturing events.
    Requires Linux with eBPF support (monitor.sh).
    """
    if platform.system() != "Linux":
        print("❌ Live scanning requires Linux (eBPF)")
        print("On macOS, you can only scan existing trace files:")
        print(f"  python -m scbf.detection.cli --trace path/to/trace.jsonl")
        sys.exit(1)
    
    if not os.path.exists("monitor.sh"):
        print("❌ monitor.sh not found - required for live capture")
        sys.exit(1)
    
    # Setup sandbox
    shutil.rmtree(target_dir, ignore_errors=True)
    os.makedirs(target_dir, exist_ok=True)
    
    trace_output = f"/tmp/scbf_scan_{pkg_name}.jsonl"
    
    print(f"📦 Installing {pkg_name} with behavioral monitoring...")
    print(f"   Target: {target_dir}")
    print(f"   Trace:  {trace_output}")
    
    try:
        subprocess.run(
            ["sudo", "./monitor.sh", pkg_name, trace_output],
            check=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        print("⚠️  Installation timed out")
    except subprocess.CalledProcessError as e:
        print(f"⚠️  Install returned {e.returncode} - analyzing partial trace")
    except FileNotFoundError:
        print("❌ Failed to run monitor.sh")
        return None
    
    if not os.path.exists(trace_output):
        print(f"❌ No trace file created")
        return None
    
    # Scan the captured trace
    return scan_trace_file(trace_output)


def main():
    parser = argparse.ArgumentParser(
        description="SCBF Package Scanner - Detect malicious packages via behavioral analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan an existing trace file (works on macOS and Linux)
  python -m scbf.detection.cli --trace data/zenodo_13746167/malware/traces/some_pkg.jsonl
  
  # Batch scan all traces in a directory
  python -m scbf.detection.cli --batch data/zenodo_13746167/malware/traces/
  
  # Live scan by pip installing (Linux only)
  sudo python -m scbf.detection.cli --package requests
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--trace", help="Path to existing trace file (.jsonl)")
    group.add_argument("--batch", help="Directory containing trace files to scan")
    group.add_argument("--package", help="Package name to install and scan (Linux only)")
    
    parser.add_argument("--model", default="models/scbf_hybrid_v2.pt",
                       help="Path to trained model")
    parser.add_argument("--envelope", default="models/envelope_v2.npy",
                       help="Path to behavioral envelope")
    
    args = parser.parse_args()
    
    if args.trace:
        if not os.path.exists(args.trace):
            print(f"❌ Trace file not found: {args.trace}")
            sys.exit(1)
        scan_trace_file(args.trace)
    
    elif args.batch:
        if not os.path.isdir(args.batch):
            print(f"❌ Directory not found: {args.batch}")
            sys.exit(1)
        batch_scan(args.batch)
    
    elif args.package:
        scan_package_live(args.package)


if __name__ == "__main__":
    main()
