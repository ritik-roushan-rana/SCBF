"""
Hybrid Model: TGN Embedding + Statistical Features

This approach combines:
1. TGN embedding (temporal graph info)
2. Statistical features (event counts, entropy, etc.)
3. Neural classifier

Much more discriminative than TGN alone.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import glob
import json
import random
import os
import numpy as np
from collections import Counter
from datetime import datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.tgn_encoder import TGNEncoder
from models.itbg_constructor import ITBGConstructor


def extract_statistical_features(events):
    """Extract hand-crafted features from events."""
    if not events:
        return np.zeros(20)
    
    features = []
    
    # 1-4: Event counts
    n_events = len(events)
    event_types = Counter(e.get('type', 'unknown') for e in events)
    features.append(n_events)
    features.append(event_types.get('exec', 0))
    features.append(event_types.get('open', 0))
    features.append(event_types.get('connect', 0))
    
    # 5-7: Ratios
    features.append(event_types.get('exec', 0) / max(1, n_events))
    features.append(event_types.get('open', 0) / max(1, n_events))
    features.append(event_types.get('connect', 0) / max(1, n_events))
    
    # 8-10: Unique counts
    unique_pids = len(set(e.get('pid', 0) for e in events))
    unique_comms = len(set(e.get('comm', '') for e in events))
    unique_files = len(set(e.get('fname', '') for e in events if e.get('fname')))
    features.append(unique_pids)
    features.append(unique_comms)
    features.append(unique_files)
    
    # 11-13: File path analysis
    paths = [e.get('fname', '') for e in events if e.get('fname')]
    n_tmp_paths = sum(1 for p in paths if '/tmp/' in p or '/var/tmp/' in p)
    n_hidden_paths = sum(1 for p in paths if '/.' in p)
    n_system_paths = sum(1 for p in paths if p.startswith('/usr/') or p.startswith('/etc/'))
    features.append(n_tmp_paths)
    features.append(n_hidden_paths)
    features.append(n_system_paths)
    
    # 14-16: Network activity
    n_connects = event_types.get('connect', 0)
    features.append(n_connects)
    features.append(int(n_connects > 0))
    features.append(n_connects / max(1, n_events))
    
    # 17-18: Process behavior
    comms = [e.get('comm', '') for e in events]
    suspicious_comms = ['curl', 'wget', 'nc', 'ncat', 'bash', 'sh', 'python', 'perl']
    n_suspicious = sum(1 for c in comms if any(s in c.lower() for s in suspicious_comms))
    features.append(n_suspicious)
    features.append(n_suspicious / max(1, n_events))
    
    # 19-20: Time-based features
    timestamps = [e.get('ts', 0) for e in events if e.get('ts')]
    if len(timestamps) > 1:
        duration = max(timestamps) - min(timestamps)
        events_per_sec = n_events / max(1, duration / 1e9)
    else:
        duration = 0
        events_per_sec = 0
    features.append(np.log1p(duration))
    features.append(np.log1p(events_per_sec))
    
    return np.array(features, dtype=np.float32)


class HybridClassifier(nn.Module):
    """Combines TGN embedding + statistical features for classification."""
    
    def __init__(self, num_nodes=50000, embedding_dim=128, stat_dim=20):
        super().__init__()
        self.tgn = TGNEncoder(num_nodes=num_nodes, out_dim=embedding_dim)
        
        # Statistical feature encoder
        self.stat_encoder = nn.Sequential(
            nn.Linear(stat_dim, 32),
            nn.LayerNorm(32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 32),
            nn.LayerNorm(32),
            nn.ReLU(),
        )
        
        # Combined classifier
        combined_dim = embedding_dim + 32
        self.classifier = nn.Sequential(
            nn.Linear(combined_dim, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.LayerNorm(32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 1)
        )
        
        # Initialize
        nn.init.zeros_(self.classifier[-1].bias)
        nn.init.xavier_uniform_(self.classifier[-1].weight, gain=0.1)
    
    def forward(self, events):
        # TGN embedding
        self.tgn.memory_bank.reset_memory()
        constructor = ITBGConstructor(self.tgn)
        tgn_emb = constructor.replay_session(events)
        
        if tgn_emb is None:
            return None, None
        
        # Statistical features
        stat_features = extract_statistical_features(events)
        stat_tensor = torch.from_numpy(stat_features)
        # Normalize
        stat_tensor = (stat_tensor - stat_tensor.mean()) / (stat_tensor.std() + 1e-6)
        
        # Encode stats
        stat_emb = self.stat_encoder(stat_tensor)
        
        # Combine
        combined = torch.cat([tgn_emb, stat_emb], dim=-1)
        
        # Classify
        logits = self.classifier(combined)
        
        return combined, logits


class BalancedBCELoss(nn.Module):
    def __init__(self, pos_weight=1.0):
        super().__init__()
        self.pos_weight = torch.tensor(pos_weight)
    
    def forward(self, logits, targets):
        return F.binary_cross_entropy_with_logits(
            logits, targets, pos_weight=self.pos_weight
        )


def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def load_events(path):
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]


def split_data(clean_paths, mal_paths, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=42):
    set_seed(seed)
    clean_shuffled = clean_paths.copy()
    mal_shuffled = mal_paths.copy()
    random.shuffle(clean_shuffled)
    random.shuffle(mal_shuffled)
    
    n_clean = len(clean_shuffled)
    n_mal = len(mal_shuffled)
    
    clean_train_end = int(n_clean * train_ratio)
    clean_val_end = int(n_clean * (train_ratio + val_ratio))
    mal_train_end = int(n_mal * train_ratio)
    mal_val_end = int(n_mal * (train_ratio + val_ratio))
    
    train_set = ([(p, 0) for p in clean_shuffled[:clean_train_end]] + 
                 [(p, 1) for p in mal_shuffled[:mal_train_end]])
    val_set = ([(p, 0) for p in clean_shuffled[clean_train_end:clean_val_end]] + 
               [(p, 1) for p in mal_shuffled[mal_train_end:mal_val_end]])
    test_set = ([(p, 0) for p in clean_shuffled[clean_val_end:]] + 
                [(p, 1) for p in mal_shuffled[mal_val_end:]])
    
    random.shuffle(train_set)
    random.shuffle(val_set)
    random.shuffle(test_set)
    return train_set, val_set, test_set


def compute_metrics(logits, labels, threshold=0.5):
    probs = torch.sigmoid(logits)
    predictions = (probs > threshold).long()
    labels_int = labels.long()
    
    tp = ((predictions == 1) & (labels_int == 1)).sum().item()
    tn = ((predictions == 0) & (labels_int == 0)).sum().item()
    fp = ((predictions == 1) & (labels_int == 0)).sum().item()
    fn = ((predictions == 0) & (labels_int == 1)).sum().item()
    
    accuracy = (tp + tn) / len(labels) if len(labels) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'accuracy': accuracy, 'precision': precision, 'recall': recall, 'f1': f1,
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn
    }


def train_epoch(model, optimizer, loss_fn, train_set, batch_size=16):
    model.train()
    balanced_set = list(train_set)
    random.shuffle(balanced_set)
    
    all_logits = []
    all_labels = []
    total_loss = 0
    num_batches = 0
    batch_logits = []
    batch_labels = []
    
    for i, (path, label) in enumerate(balanced_set):
        try:
            events = load_events(path)
            embedding, logits = model(events)
            
            if embedding is not None and logits is not None:
                batch_logits.append(logits.squeeze())
                batch_labels.append(float(label))
                
                if len(batch_logits) >= batch_size or i == len(balanced_set) - 1:
                    if len(batch_logits) >= 2:
                        logits_tensor = torch.stack(batch_logits)
                        labels_tensor = torch.tensor(batch_labels)
                        loss = loss_fn(logits_tensor, labels_tensor)
                        
                        optimizer.zero_grad()
                        loss.backward()
                        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                        optimizer.step()
                        
                        all_logits.extend([l.detach() for l in batch_logits])
                        all_labels.extend(batch_labels)
                        total_loss += loss.item()
                        num_batches += 1
                    
                    batch_logits = []
                    batch_labels = []
        except Exception as e:
            continue
    
    if len(all_logits) < 2:
        return {'loss': float('inf'), 'accuracy': 0, 'recall': 0, 'f1': 0}
    
    logits = torch.stack(all_logits)
    labels = torch.tensor(all_labels)
    metrics = compute_metrics(logits, labels)
    metrics['loss'] = total_loss / max(1, num_batches)
    return metrics


def evaluate(model, loss_fn, data_set):
    model.eval()
    all_logits = []
    all_labels = []
    
    with torch.no_grad():
        for path, label in data_set:
            try:
                events = load_events(path)
                embedding, logits = model(events)
                if embedding is not None and logits is not None:
                    all_logits.append(logits.squeeze())
                    all_labels.append(float(label))
            except:
                continue
    
    if len(all_logits) < 2:
        return {'loss': float('inf'), 'accuracy': 0, 'recall': 0, 'f1': 0}
    
    logits = torch.stack(all_logits)
    labels = torch.tensor(all_labels)
    loss = loss_fn(logits, labels)
    metrics = compute_metrics(logits, labels)
    metrics['loss'] = loss.item()
    metrics['n_samples'] = len(labels)
    return metrics


def main():
    SEED = 42
    TRAIN_RATIO = 0.7
    VAL_RATIO = 0.15
    TEST_RATIO = 0.15
    LEARNING_RATE = 5e-4
    EPOCHS = 30
    PATIENCE = 5
    NUM_NODES = 50000
    CHECKPOINT_DIR = "models/checkpoints"
    
    set_seed(SEED)
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    
    print("Loading data...")
    clean_paths = glob.glob("data/zenodo_13746167/benign/traces/*.jsonl")
    mal_paths = glob.glob("data/zenodo_13746167/malware/traces/*.jsonl")
    
    print(f"Benign: {len(clean_paths)}")
    print(f"Malware: {len(mal_paths)}")
    
    if len(clean_paths) == 0 or len(mal_paths) == 0:
        return
    
    train_set, val_set, test_set = split_data(
        clean_paths, mal_paths, TRAIN_RATIO, VAL_RATIO, TEST_RATIO, seed=SEED
    )
    
    print(f"\nSplits:")
    print(f"  Train: {len(train_set)}")
    print(f"  Val:   {len(val_set)}")
    print(f"  Test:  {len(test_set)}")
    
    # Initialize hybrid model
    print("\nInitializing HYBRID model (TGN + Statistical Features)...")
    model = HybridClassifier(num_nodes=NUM_NODES)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='min', factor=0.5, patience=3
    )
    
    n_clean = sum(1 for _, l in train_set if l == 0)
    n_mal = sum(1 for _, l in train_set if l == 1)
    pos_weight = n_clean / max(1, n_mal)
    print(f"Using pos_weight={pos_weight:.2f}")
    loss_fn = BalancedBCELoss(pos_weight=pos_weight)
    
    print(f"\nTraining (max {EPOCHS} epochs, patience={PATIENCE})")
    print("=" * 80)
    
    best_val_f1 = 0
    epochs_without_improvement = 0
    
    for epoch in range(EPOCHS):
        train_metrics = train_epoch(model, optimizer, loss_fn, train_set)
        val_metrics = evaluate(model, loss_fn, val_set)
        scheduler.step(val_metrics['loss'])
        
        print(f"\nEpoch {epoch + 1}/{EPOCHS}")
        print(f"  Train: loss={train_metrics['loss']:.4f}, acc={train_metrics['accuracy']:.2%}, "
              f"recall={train_metrics['recall']:.2%}, f1={train_metrics['f1']:.2%}")
        print(f"  Val:   loss={val_metrics['loss']:.4f}, acc={val_metrics['accuracy']:.2%}, "
              f"recall={val_metrics['recall']:.2%}, f1={val_metrics['f1']:.2%}")
        
        current_f1 = val_metrics['f1']
        if current_f1 > best_val_f1:
            best_val_f1 = current_f1
            epochs_without_improvement = 0
            
            best_path = os.path.join(CHECKPOINT_DIR, "hybrid_best.pt")
            torch.save({
                'epoch': epoch + 1,
                'model_state_dict': model.state_dict(),
                'val_metrics': val_metrics,
            }, best_path)
            print(f"  ✓ New best (F1={current_f1:.2%})")
        else:
            epochs_without_improvement += 1
            print(f"  No improvement ({epochs_without_improvement}/{PATIENCE})")
        
        if epochs_without_improvement >= PATIENCE:
            print(f"\nEarly stopping at epoch {epoch + 1}")
            break
    
    # Test
    print("\n" + "=" * 80)
    print("Loading best model for testing...")
    best_checkpoint = torch.load(os.path.join(CHECKPOINT_DIR, "hybrid_best.pt"))
    model.load_state_dict(best_checkpoint['model_state_dict'])
    
    test_metrics = evaluate(model, loss_fn, test_set)
    
    print("\n" + "=" * 80)
    print("FINAL TEST RESULTS (Hybrid Model)")
    print("=" * 80)
    print(f"Loss:      {test_metrics['loss']:.4f}")
    print(f"Accuracy:  {test_metrics['accuracy']:.2%}")
    print(f"Precision: {test_metrics['precision']:.2%}")
    print(f"Recall:    {test_metrics['recall']:.2%}")
    print(f"F1 Score:  {test_metrics['f1']:.2%}")
    print(f"\nConfusion Matrix:")
    print(f"                Predicted")
    print(f"              Clean  Malicious")
    print(f"Actual Clean    {test_metrics['tn']:3d}  {test_metrics['fp']:3d}")
    print(f"Actual Mal      {test_metrics['fn']:3d}  {test_metrics['tp']:3d}")
    print("=" * 80)
    
    torch.save(model.state_dict(), "models/scbf_hybrid.pt")
    print(f"\nBest model saved to: models/scbf_hybrid.pt")
    print(f"Best val F1: {best_val_f1:.2%}")
    print(f"Test F1: {test_metrics['f1']:.2%}")


if __name__ == "__main__":
    main()
