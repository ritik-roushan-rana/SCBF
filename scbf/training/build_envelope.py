"""
ild Behavioral Envelope from clean package traces.

Per Patent Spec (Section 08.3):
- Run clean packages through the encoder
- Compute centroid (mean) and covariance of DNA vectors
- Store as Behavioral Envelope Profile (BEP)
- Set anomaly threshold at mean + 2.5 std dev

The envelope represents "what packages of this type normally do".
Malicious packages deviate from this envelope, triggering detection.
"""

import torch
import glob
import json
import numpy as np
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.tgn_encoder import TGNEncoder
from models.itbg_constructor import ITBGConstructor
from training.train_hybrid_v2 import HybridClassifierV2, extract_features_v2, load_events


def compute_dna_vectors(model, paths, use_tgn_only=False):
    """
    Extract DNA vectors from packages using the trained model.
    
    Args:
        model: Trained HybridClassifierV2 or TGNEncoder
        paths: List of trace file paths
        use_tgn_only: If True, use only TGN embedding (not full hybrid)
    
    Returns:
        numpy array of DNA vectors
    """
    vectors = []
    processed = 0
    failed = 0
    
    print(f"Extracting DNA vectors from {len(paths)} packages...")
    
    with torch.no_grad():
        for i, path in enumerate(paths):
            if (i + 1) % 50 == 0:
                print(f"  Processed {i + 1}/{len(paths)} (success: {processed}, failed: {failed})")
            
            try:
                events = load_events(path)
                
                if use_tgn_only:
                    # Extract only TGN embedding
                    model.tgn.memory_bank.reset_memory()
                    constructor = ITBGConstructor(model.tgn)
                    dna = constructor.replay_session(events)
                    
                    if dna is not None:
                        vectors.append(dna.cpu().numpy())
                        processed += 1
                    else:
                        failed += 1
                else:
                    # Extract full hybrid embedding
                    combined, logits = model(events)
                    
                    if combined is not None:
                        vectors.append(combined.cpu().numpy())
                        processed += 1
                    else:
                        failed += 1
                
            except Exception as e:
                failed += 1
                if failed <= 3:
                    print(f"  WARNING: {path}: {e}")
                continue
    
    print(f"\n✓ Successfully processed: {processed}")
    print(f"✗ Failed: {failed}")
    
    return np.array(vectors)


def build_envelope(vectors, name="envelope"):
    """
    Build behavioral envelope from DNA vectors.
    
    Per spec:
    - Compute centroid (mean)
    - Compute covariance matrix
    - Threshold = mean_distance + 2.5 * std_distance
    
    Returns:
        Dictionary with envelope statistics
    """
    print(f"\nBuilding {name} envelope from {len(vectors)} vectors...")
    
    # Compute centroid
    centroid = vectors.mean(axis=0)
    
    # Compute distances from each vector to centroid
    distances = np.sqrt(((vectors - centroid) ** 2).sum(axis=1))
    
    # Threshold: mean + 2.5 * std (per spec Section 08.3)
    mean_dist = distances.mean()
    std_dist = distances.std()
    threshold = mean_dist + 2.5 * std_dist
    
    # Also compute covariance for advanced analysis
    covariance = np.cov(vectors.T)
    
    envelope = {
        'name': name,
        'centroid': centroid,
        'covariance': covariance,
        'mean_distance': float(mean_dist),
        'std_distance': float(std_dist),
        'threshold': float(threshold),
        'n_samples': len(vectors),
        'dim': vectors.shape[1] if len(vectors) > 0 else 0,
    }
    
    print(f"  Centroid shape: {centroid.shape}")
    print(f"  Mean distance: {mean_dist:.4f}")
    print(f"  Std distance: {std_dist:.4f}")
    print(f"  Threshold (mean + 2.5*std): {threshold:.4f}")
    
    return envelope


def save_envelope(envelope, output_dir="models", suffix=""):
    """Save envelope to disk with optional suffix."""
    os.makedirs(output_dir, exist_ok=True)
    
    prefix = f"envelope_v2{suffix}"
    
    # Save centroid as numpy array (main envelope)
    centroid_path = os.path.join(output_dir, f"{prefix}.npy")
    np.save(centroid_path, envelope['centroid'])
    print(f"\n✓ Centroid saved to: {centroid_path}")
    
    # Save full envelope info
    info = {
        'name': envelope['name'],
        'mean_distance': envelope['mean_distance'],
        'std_distance': envelope['std_distance'],
        'threshold': envelope['threshold'],
        'n_samples': envelope['n_samples'],
        'dim': envelope['dim'],
    }
    
    info_path = os.path.join(output_dir, f"{prefix}_info.json")
    with open(info_path, 'w') as f:
        json.dump(info, f, indent=2)
    print(f"✓ Envelope info saved to: {info_path}")
    
    # Save covariance separately (can be large)
    cov_path = os.path.join(output_dir, f"{prefix}_covariance.npy")
    np.save(cov_path, envelope['covariance'])
    print(f"✓ Covariance saved to: {cov_path}")


def test_envelope_against_malware(model, envelope, mal_paths, threshold, use_tgn_only=False):
    """
    Test how well the envelope distinguishes clean vs malicious.
    
    Malicious packages should have distances > threshold.
    """
    print("\n" + "=" * 80)
    print("TESTING ENVELOPE AGAINST MALICIOUS PACKAGES")
    print("=" * 80)
    
    print(f"\nProcessing {len(mal_paths)} malicious samples...")
    mal_vectors = compute_dna_vectors(model, mal_paths[:50], use_tgn_only=use_tgn_only)  # Test 50
    
    if len(mal_vectors) == 0:
        print("No malicious vectors extracted")
        return
    
    # Compute distances from centroid
    distances = np.sqrt(((mal_vectors - envelope['centroid']) ** 2).sum(axis=1))
    
    # Check how many exceed threshold
    n_detected = (distances > threshold).sum()
    detection_rate = n_detected / len(distances)
    
    print(f"\nResults:")
    print(f"  Malicious samples tested: {len(mal_vectors)}")
    print(f"  Threshold: {threshold:.4f}")
    print(f"  Malicious mean distance: {distances.mean():.4f}")
    print(f"  Malicious std distance: {distances.std():.4f}")
    print(f"  Detected as anomalous: {n_detected}/{len(distances)} ({detection_rate:.1%})")
    
    if detection_rate > 0.7:
        print(f"\n✅ Envelope works well! {detection_rate:.1%} detection rate")
    elif detection_rate > 0.5:
        print(f"\n⚠️  Envelope moderate. {detection_rate:.1%} detection rate")
    else:
        print(f"\n❌ Envelope needs improvement. Only {detection_rate:.1%} detection")


def main():
    print("=" * 80)
    print("BEHAVIORAL ENVELOPE CONSTRUCTION")
    print("Per Patent Spec Section 08.3")
    print("Using TGN (Temporal Graph Network) architecture")
    print("=" * 80)
    
    MODEL_PATH = "models/scbf_hybrid_v2.pt"
    OUTPUT_DIR = "models"
    NUM_NODES = 50000
    BUILD_BOTH = True  # Build both Pure TGN and Hybrid envelopes
    USE_TGN_ONLY = False  # Only used if BUILD_BOTH = False
    
    # Check model exists
    if not os.path.exists(MODEL_PATH):
        print(f"\n❌ ERROR: Model not found at {MODEL_PATH}")
        print("Please train the model first: make train-hybrid-v2")
        return
    
    # Load model
    print(f"\nLoading model: {MODEL_PATH}")
    model = HybridClassifierV2(num_nodes=NUM_NODES)
    model.load_state_dict(torch.load(MODEL_PATH))
    model.eval()
    print("✓ Model loaded")
    print(f"✓ TGN architecture: {'Pure TGN' if USE_TGN_ONLY else 'Hybrid (TGN + statistical features)'}")
    
    # Get clean package paths
    #
    # Two sources are combined:
    #   1. Zenodo dataset traces (offline, dataset-quality reference)
    #   2. Locally-captured live traces (calibrates the envelope to the
    #      actual VM's pip / python / path layout so that live scans on
    #      this host don't drift out of distribution)
    clean_paths = (
        glob.glob("data/zenodo_13746167/benign/traces/*.jsonl")
        + glob.glob("data/traces/live_benign/*.jsonl")
    )
    mal_paths = glob.glob("data/zenodo_13746167/malware/traces/*.jsonl")

    live_count = len(glob.glob("data/traces/live_benign/*.jsonl"))
    zenodo_count = len(clean_paths) - live_count

    print(f"\nFound {zenodo_count} Zenodo clean packages")
    print(f"Found {live_count} live-captured clean packages")
    print(f"Found {len(mal_paths)} malicious packages")
    
    if len(clean_paths) == 0:
        print("❌ No clean packages found!")
        return
    
    if BUILD_BOTH:
        # Build both Pure TGN and Hybrid envelopes
        print("\n" + "=" * 80)
        print("BUILDING BOTH ENVELOPES: Pure TGN + Hybrid")
        print("=" * 80)
        
        # ─── PURE TGN ENVELOPE (Per Patent Spec) ───
        print("\n" + "─" * 80)
        print("STEP 1a: Extract PURE TGN DNA vectors")
        print("─" * 80)
        clean_vectors_tgn = compute_dna_vectors(model, clean_paths, use_tgn_only=True)
        
        print("\n" + "─" * 80)
        print("STEP 2a: Build PURE TGN Envelope")
        print("─" * 80)
        envelope_tgn = build_envelope(clean_vectors_tgn, name="pure_tgn")
        save_envelope(envelope_tgn, output_dir=OUTPUT_DIR, suffix="_tgn")
        
        # ─── HYBRID ENVELOPE (Full Model) ───
        print("\n" + "─" * 80)
        print("STEP 1b: Extract HYBRID vectors (TGN + Stats)")
        print("─" * 80)
        clean_vectors_hybrid = compute_dna_vectors(model, clean_paths, use_tgn_only=False)
        
        print("\n" + "─" * 80)
        print("STEP 2b: Build HYBRID Envelope")
        print("─" * 80)
        envelope_hybrid = build_envelope(clean_vectors_hybrid, name="hybrid")
        save_envelope(envelope_hybrid, output_dir=OUTPUT_DIR, suffix="_hybrid")
        
        # ─── TEST BOTH ───
        print("\n" + "─" * 80)
        print("STEP 3a: Test PURE TGN Envelope")
        print("─" * 80)
        test_envelope_against_malware(model, envelope_tgn, mal_paths, envelope_tgn['threshold'], use_tgn_only=True)
        
        print("\n" + "─" * 80)
        print("STEP 3b: Test HYBRID Envelope")
        print("─" * 80)
        test_envelope_against_malware(model, envelope_hybrid, mal_paths, envelope_hybrid['threshold'], use_tgn_only=False)
        
        # Save default (hybrid) as main envelope
        save_envelope(envelope_hybrid, output_dir=OUTPUT_DIR, suffix="")
        
        print("\n" + "=" * 80)
        print("COMPARISON SUMMARY")
        print("=" * 80)
        print(f"""
Pure TGN Envelope:
  Dimension: {envelope_tgn['dim']}
  Mean distance: {envelope_tgn['mean_distance']:.4f}
  Threshold:     {envelope_tgn['threshold']:.4f}
  Files:         envelope_v2_tgn.npy

Hybrid Envelope:
  Dimension: {envelope_hybrid['dim']}
  Mean distance: {envelope_hybrid['mean_distance']:.4f}
  Threshold:     {envelope_hybrid['threshold']:.4f}
  Files:         envelope_v2_hybrid.npy

Default envelope (envelope_v2.npy) = Hybrid (best performance)
""")
    else:
        # Build single envelope
        print("\n" + "=" * 80)
        print(f"STEP 1: Extract DNA vectors ({'Pure TGN' if USE_TGN_ONLY else 'Hybrid'})")
        print("=" * 80)
        
        clean_vectors = compute_dna_vectors(model, clean_paths, use_tgn_only=USE_TGN_ONLY)
        
        if len(clean_vectors) == 0:
            print("❌ Failed to extract any vectors")
            return
        
        envelope = build_envelope(clean_vectors, name="clean_pypi")
        save_envelope(envelope, output_dir=OUTPUT_DIR)
        test_envelope_against_malware(model, envelope, mal_paths, envelope['threshold'], use_tgn_only=USE_TGN_ONLY)
    
    # Summary
    print("\n" + "=" * 80)
    print("ENVELOPE BUILD COMPLETE")
    print("=" * 80)
    print(f"""
✓ Behavioral envelopes built successfully
✓ Saved to: {OUTPUT_DIR}/

Files created:
  - envelope_v2.npy           (default = hybrid)
  - envelope_v2_tgn.npy       (Pure TGN, 128-dim)
  - envelope_v2_hybrid.npy    (Hybrid, 192-dim)
  - envelope_v2_*_info.json   (thresholds & stats)
  - envelope_v2_*_covariance.npy (covariance matrices)

Usage for detection:
  1. Compute DNA vector for new package
  2. Compute distance to centroid
  3. If distance > threshold: MALICIOUS
  4. Else: BENIGN

Next steps:
  - Use models/envelope_v2.npy for scanning
  - Run: make scan PKG=<package_name>
  - Deploy for CI/CD integration
""")


if __name__ == "__main__":
    main()
