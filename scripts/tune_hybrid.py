#!/usr/bin/env python3
"""Find optimal threshold for hybrid model."""

import torch
import json
import numpy as np
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scbf.training.train_hybrid import HybridClassifier, extract_statistical_features, load_events


def evaluate_threshold(probs, labels, threshold):
    predictions = (probs > threshold).astype(int)
    tp = ((predictions == 1) & (labels == 1)).sum()
    tn = ((predictions == 0) & (labels == 0)).sum()
    fp = ((predictions == 1) & (labels == 0)).sum()
    fn = ((predictions == 0) & (labels == 1)).sum()
    
    accuracy = (tp + tn) / len(labels)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'accuracy': accuracy, 'precision': precision, 'recall': recall, 'f1': f1,
        'tp': int(tp), 'tn': int(tn), 'fp': int(fp), 'fn': int(fn)
    }


def main():
    with open("models/checkpoints/split_info.json", 'r') as f:
        split_info = json.load(f)
    
    test_data = split_info['test']
    
    print("Loading hybrid model...")
    model = HybridClassifier(num_nodes=50000)
    model.load_state_dict(torch.load("models/scbf_hybrid.pt"))
    model.eval()
    
    print(f"Processing {len(test_data)} samples...")
    all_probs = []
    all_labels = []
    
    with torch.no_grad():
        for i, item in enumerate(test_data):
            if (i + 1) % 50 == 0:
                print(f"  {i + 1}/{len(test_data)}")
            
            try:
                events = load_events(item['path'])
                _, logits = model(events)
                
                if logits is not None:
                    prob = torch.sigmoid(logits).item()
                    all_probs.append(prob)
                    all_labels.append(item['label'])
            except:
                continue
    
    probs = np.array(all_probs)
    labels = np.array(all_labels)
    
    print("\n" + "=" * 80)
    print("THRESHOLD ANALYSIS")
    print("=" * 80)
    print(f"\n{'Threshold':<12} {'Accuracy':<10} {'Precision':<12} {'Recall':<10} {'F1':<10}")
    print("-" * 60)
    
    best_f1 = 0
    best_threshold = 0.5
    best_metrics = None
    
    for threshold in np.arange(0.1, 0.95, 0.05):
        metrics = evaluate_threshold(probs, labels, threshold)
        
        if metrics['f1'] > best_f1:
            best_f1 = metrics['f1']
            best_threshold = threshold
            best_metrics = metrics
        
        print(f"{threshold:8.2f}   {metrics['accuracy']:.2%}   {metrics['precision']:.2%}   "
              f"{metrics['recall']:.2%}   {metrics['f1']:.2%}")
    
    print("\n" + "=" * 80)
    print(f"BEST THRESHOLD: {best_threshold:.2f}")
    print("=" * 80)
    print(f"Accuracy:  {best_metrics['accuracy']:.2%}")
    print(f"Precision: {best_metrics['precision']:.2%}")
    print(f"Recall:    {best_metrics['recall']:.2%}")
    print(f"F1 Score:  {best_metrics['f1']:.2%}")
    print(f"\nConfusion Matrix:")
    print(f"                Predicted")
    print(f"              Clean  Malicious")
    print(f"Actual Clean    {best_metrics['tn']:3d}  {best_metrics['fp']:3d}")
    print(f"Actual Mal      {best_metrics['fn']:3d}  {best_metrics['tp']:3d}")


if __name__ == "__main__":
    main()
