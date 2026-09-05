#!/usr/bin/env python3
"""Quick evaluation on test set only."""

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
    
    print(f"Processing {len(data_list)} samples...")
    for i, item in enumerate(data_list):
        if (i + 1) % 50 == 0:
            print(f"  Processed {i + 1}/{len(data_list)}...")
        
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
        except Exception as e:
            print(f"  WARNING: Failed {path}: {e}")
            continue
    
    if len(embeddings_list) == 0:
        return None, None
    
    return np.array(embeddings_list), np.array(labels_list)


def main():
    # Load split info
    with open("models/checkpoints/split_info.json", 'r') as f:
        split_info = json.load(f)
    
    test_data = split_info['test']
    
    print(f"Test set: {len(test_data)} samples")
    print(f"  Clean: {sum(1 for x in test_data if x['label'] == 0)}")
    print(f"  Malicious: {sum(1 for x in test_data if x['label'] == 1)}")
    
    # Load model
    print("\nLoading model...")
    model = TGNEncoder(num_nodes=50000)
    model.load_state_dict(torch.load("models/tgn_v2_best.pt"))
    model.eval()
    
    # Compute embeddings
    print("\nComputing embeddings...")
    with torch.no_grad():
        embeddings, labels = compute_embeddings(model, test_data)
    
    if embeddings is None:
        print("ERROR: No valid samples")
        return
    
    # Compute clean centroid and distances
    clean_mask = labels == 0
    clean_centroid = embeddings[clean_mask].mean(axis=0)
    distances = np.sqrt(((embeddings - clean_centroid) ** 2).sum(axis=1))
    
    # Distance statistics
    clean_dists = distances[labels == 0]
    mal_dists = distances[labels == 1]
    
    print("\n" + "=" * 80)
    print("DISTANCE STATISTICS")
    print("=" * 80)
    print(f"Clean distances: mean={clean_dists.mean():.4f}, std={clean_dists.std():.4f}")
    print(f"Malicious distances: mean={mal_dists.mean():.4f}, std={mal_dists.std():.4f}")
    
    # Auto-threshold: clean mean + 2*std
    threshold = clean_dists.mean() + 2 * clean_dists.std()
    print(f"\nAuto-computed threshold: {threshold:.4f}")
    
    # Predictions
    predictions = (distances > threshold).astype(int)
    
    # Confusion matrix
    tp = ((predictions == 1) & (labels == 1)).sum()
    tn = ((predictions == 0) & (labels == 0)).sum()
    fp = ((predictions == 1) & (labels == 0)).sum()
    fn = ((predictions == 0) & (labels == 1)).sum()
    
    # Metrics
    accuracy = (tp + tn) / len(labels)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print("\n" + "=" * 80)
    print("TEST SET RESULTS")
    print("=" * 80)
    print(f"\nAccuracy:  {accuracy:.2%} ({accuracy:.4f})")
    print(f"Precision: {precision:.2%} ({precision:.4f})")
    print(f"Recall:    {recall:.2%} ({recall:.4f})")
    print(f"F1 Score:  {f1:.2%} ({f1:.4f})")
    print(f"FPR:       {fpr:.2%} ({fpr:.4f})")
    
    print(f"\nConfusion Matrix:")
    print(f"                Predicted")
    print(f"              Clean  Malicious")
    print(f"Actual Clean    {tn:3d}  {fp:3d}")
    print(f"Actual Mal      {fn:3d}  {tp:3d}")
    
    # Try AUC
    try:
        from sklearn.metrics import roc_auc_score
        auc = roc_auc_score(labels, distances)
        print(f"\nROC-AUC: {auc:.4f}")
    except:
        pass
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
