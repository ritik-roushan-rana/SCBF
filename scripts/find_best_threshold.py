#!/usr/bin/env python3
"""Find optimal threshold for best F1 score."""

import torch
import json
import numpy as np
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from scbf.models.tgn_encoder import TGNEncoder
from scbf.models.itbg_constructor import ITBGConstructor


def load_events(path):
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]


def compute_embeddings(model, data_list):
    embeddings_list = []
    labels_list = []
    
    for item in data_list:
        path = item['path']
        label = item['label']
        
        model.memory_bank.reset_memory()
        constructor = ITBGConstructor(model)
        
        try:
            events = load_events(path)
            dna = constructor.replay_session(events)
            
            if dna is not None:
                embeddings_list.append(dna.detach().cpu().numpy())
                labels_list.append(label)
        except:
            continue
    
    return np.array(embeddings_list), np.array(labels_list)


def evaluate_threshold(distances, labels, threshold):
    predictions = (distances > threshold).astype(int)
    
    tp = ((predictions == 1) & (labels == 1)).sum()
    tn = ((predictions == 0) & (labels == 0)).sum()
    fp = ((predictions == 1) & (labels == 0)).sum()
    fn = ((predictions == 0) & (labels == 1)).sum()
    
    accuracy = (tp + tn) / len(labels)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'fpr': fpr,
        'tp': int(tp),
        'tn': int(tn),
        'fp': int(fp),
        'fn': int(fn)
    }


def main():
    # Load split info
    with open("models/checkpoints/split_info.json", 'r') as f:
        split_info = json.load(f)
    
    test_data = split_info['test']
    
    print("Loading model and computing embeddings...")
    model = TGNEncoder(num_nodes=50000)
    model.load_state_dict(torch.load("models/tgn_v2_best.pt"))
    model.eval()
    
    with torch.no_grad():
        embeddings, labels = compute_embeddings(model, test_data)
    
    # Compute clean centroid and distances
    clean_mask = labels == 0
    clean_centroid = embeddings[clean_mask].mean(axis=0)
    distances = np.sqrt(((embeddings - clean_centroid) ** 2).sum(axis=1))
    
    clean_dists = distances[labels == 0]
    mal_dists = distances[labels == 1]
    
    print("\n" + "=" * 80)
    print("DISTANCE ANALYSIS")
    print("=" * 80)
    print(f"Clean: mean={clean_dists.mean():.4f}, std={clean_dists.std():.4f}, "
          f"min={clean_dists.min():.4f}, max={clean_dists.max():.4f}")
    print(f"Mal:   mean={mal_dists.mean():.4f}, std={mal_dists.std():.4f}, "
          f"min={mal_dists.min():.4f}, max={mal_dists.max():.4f}")
    
    # Test multiple thresholds
    print("\n" + "=" * 80)
    print("TESTING DIFFERENT THRESHOLDS")
    print("=" * 80)
    
    best_f1 = 0
    best_threshold = 0
    best_metrics = None
    
    # Test thresholds from min to max
    test_thresholds = np.linspace(clean_dists.min(), mal_dists.max(), 50)
    
    print(f"\n{'Threshold':<12} {'Accuracy':<10} {'Precision':<12} {'Recall':<10} {'F1':<10} {'FPR':<10}")
    print("-" * 80)
    
    for threshold in test_thresholds:
        metrics = evaluate_threshold(distances, labels, threshold)
        
        if metrics['f1'] > best_f1:
            best_f1 = metrics['f1']
            best_threshold = threshold
            best_metrics = metrics
        
        # Print every 10th threshold
        if abs(threshold - test_thresholds[0]) % 0.1 < 0.02 or threshold == test_thresholds[-1]:
            print(f"{threshold:10.4f}   {metrics['accuracy']:8.2%}   {metrics['precision']:10.2%}   "
                  f"{metrics['recall']:8.2%}   {metrics['f1']:8.2%}   {metrics['fpr']:8.2%}")
    
    print("\n" + "=" * 80)
    print("BEST THRESHOLD RESULTS")
    print("=" * 80)
    print(f"\nOptimal Threshold: {best_threshold:.4f}")
    print(f"\nAccuracy:  {best_metrics['accuracy']:.2%} ({best_metrics['accuracy']:.4f})")
    print(f"Precision: {best_metrics['precision']:.2%} ({best_metrics['precision']:.4f})")
    print(f"Recall:    {best_metrics['recall']:.2%} ({best_metrics['recall']:.4f})")
    print(f"F1 Score:  {best_metrics['f1']:.2%} ({best_metrics['f1']:.4f})")
    print(f"FPR:       {best_metrics['fpr']:.2%} ({best_metrics['fpr']:.4f})")
    
    print(f"\nConfusion Matrix:")
    print(f"                Predicted")
    print(f"              Clean  Malicious")
    print(f"Actual Clean    {best_metrics['tn']:3d}  {best_metrics['fp']:3d}")
    print(f"Actual Mal      {best_metrics['fn']:3d}  {best_metrics['tp']:3d}")
    
    # Compare to automatic threshold
    auto_threshold = clean_dists.mean() + 2 * clean_dists.std()
    print(f"\n" + "=" * 80)
    print(f"Comparison:")
    print(f"  Automatic threshold (mean + 2*std): {auto_threshold:.4f}")
    print(f"  Optimal threshold (best F1):        {best_threshold:.4f}")
    print(f"  Improvement in F1:                  {best_f1 - evaluate_threshold(distances, labels, auto_threshold)['f1']:.4f}")
    print("=" * 80)


if __name__ == "__main__":
    main()
