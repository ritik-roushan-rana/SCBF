"""
Test QUT-DV25 converted samples through SCBF pipeline.

This script verifies that converted QUT-DV25 JSONL files are compatible
with the existing SCBF ITBG + TGN pipeline.
"""

import sys
import json
import glob
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scbf.models.tgn_encoder import TGNEncoder
from scbf.models.itbg_constructor import ITBGConstructor


def load_events(path):
    """Load events from JSONL file."""
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]


def test_sample(jsonl_path, model, constructor):
    """
    Test a single converted sample through the pipeline.
    
    Returns dict with test results.
    """
    result = {
        'path': jsonl_path,
        'name': Path(jsonl_path).stem,
        'success': False,
        'events_loaded': 0,
        'dna_generated': False,
        'dna_shape': None,
        'error': None
    }
    
    try:
        # Load events
        events = load_events(jsonl_path)
        result['events_loaded'] = len(events)
        
        if result['events_loaded'] == 0:
            result['error'] = "No events loaded"
            return result
        
        # Validate event format
        for i, event in enumerate(events[:10]):  # Check first 10
            if 'type' not in event or 'ts' not in event:
                result['error'] = f"Event {i} missing required fields"
                return result
        
        # Test through ITBG + TGN
        constructor.dna_history = []
        constructor.last_dna = None
        dna = constructor.replay_session(events)
        
        if dna is None:
            result['error'] = "DNA is None"
            return result
        
        result['dna_generated'] = True
        result['dna_shape'] = tuple(dna.shape)
        result['success'] = True
    
    except Exception as e:
        result['error'] = str(e)
    
    return result


def main():
    """Main test routine."""
    print("\n" + "="*80)
    print("QUT-DV25 Pipeline Integration Test")
    print("="*80)
    
    # Initialize model
    print("\nInitializing TGN encoder...")
    model = TGNEncoder(num_nodes=50000)
    constructor = ITBGConstructor(model)
    print("✓ Model initialized")
    
    # Find converted samples
    clean_samples = glob.glob("data/qut_clean/*.jsonl")
    malicious_samples = glob.glob("data/qut_malicious/*.jsonl")
    
    print(f"\nFound {len(clean_samples)} clean samples")
    print(f"Found {len(malicious_samples)} malicious samples")
    
    if len(clean_samples) == 0 and len(malicious_samples) == 0:
        print("\nERROR: No converted samples found!")
        print("Run: python scripts/convert_qutdv25.py --limit 5")
        sys.exit(1)
    
    all_samples = clean_samples + malicious_samples
    
    # Test each sample
    print(f"\n{'='*80}")
    print("Testing samples through ITBG + TGN pipeline...")
    print('='*80)
    
    results = []
    for i, sample_path in enumerate(all_samples, 1):
        print(f"\n[{i}/{len(all_samples)}] Testing {Path(sample_path).stem}...")
        
        result = test_sample(sample_path, model, constructor)
        results.append(result)
        
        if result['success']:
            print(f"  ✓ SUCCESS")
            print(f"    Events: {result['events_loaded']}")
            print(f"    DNA shape: {result['dna_shape']}")
        else:
            print(f"  ✗ FAILED: {result['error']}")
            print(f"    Events loaded: {result['events_loaded']}")
    
    # Summary
    print(f"\n{'='*80}")
    print("TEST SUMMARY")
    print('='*80)
    
    success_count = sum(1 for r in results if r['success'])
    fail_count = len(results) - success_count
    
    print(f"\nTotal samples tested: {len(results)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {fail_count}")
    
    if success_count > 0:
        avg_events = sum(r['events_loaded'] for r in results if r['success']) / success_count
        print(f"Average events/sample: {avg_events:.1f}")
        
        dna_shapes = [r['dna_shape'] for r in results if r['dna_generated']]
        if dna_shapes:
            print(f"DNA embedding shape: {dna_shapes[0]}")
            
            # Check all shapes are consistent
            if len(set(dna_shapes)) == 1:
                print("✓ All DNA embeddings have consistent shape")
            else:
                print("⚠ WARNING: Inconsistent DNA shapes detected")
    
    # List failed samples
    failed_samples = [r for r in results if not r['success']]
    if failed_samples:
        print(f"\nFailed samples:")
        for r in failed_samples:
            print(f"  - {r['name']}: {r['error']}")
    
    # Compatibility verdict
    print(f"\n{'='*80}")
    if fail_count == 0:
        print("✅ PASS: All QUT-DV25 samples compatible with SCBF pipeline")
        print("\nNext steps:")
        print("1. Convert full dataset: python scripts/convert_qutdv25.py")
        print("2. Update training: python scripts/validate_qutdv25.py")
        print("3. Train model: sudo make train-split")
    else:
        print("⚠️  PARTIAL: Some samples failed compatibility test")
        print(f"\nSuccess rate: {success_count}/{len(results)} ({100*success_count/len(results):.1f}%)")
        
        if success_count / len(results) >= 0.9:
            print("\n✓ Success rate >= 90% - acceptable for training")
            print("\nYou can proceed with full conversion:")
            print("  python scripts/convert_qutdv25.py")
        else:
            print("\n✗ Success rate < 90% - investigate failures before full conversion")
    
    print("="*80 + "\n")
    
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
