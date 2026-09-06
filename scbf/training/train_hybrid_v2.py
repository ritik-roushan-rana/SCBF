"""
Hybrid Model V2: Enhanced features + better architecture

Target: 80-90% accuracy with balanced metrics

Improvements over V1:
- 40+ statistical features (was 20)
- Deeper classifier with residual connections
- Longer training with warm-up
- Focal loss for hard examples
- Better regularization
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import glob
import json
import random
import os
import re
import numpy as np
from collections import Counter
from datetime import datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.tgn_encoder import TGNEncoder
from models.itbg_constructor import ITBGConstructor


def extract_features_v2(events):
    """Extract 45 statistical features from events."""
    if not events:
        return np.zeros(45, dtype=np.float32)
    
    features = []
    n_events = len(events)
    
    # Event type counts and ratios (1-8)
    event_types = Counter(e.get('type', '') for e in events)
    features.append(n_events)
    features.append(event_types.get('exec', 0))
    features.append(event_types.get('open', 0))
    features.append(event_types.get('connect', 0))
    features.append(event_types.get('exec', 0) / max(1, n_events))
    features.append(event_types.get('open', 0) / max(1, n_events))
    features.append(event_types.get('connect', 0) / max(1, n_events))
    features.append(len(event_types))  # Type diversity
    
    # Unique counts (9-13)
    unique_pids = set(e.get('pid', 0) for e in events)
    unique_comms = set(e.get('comm', '') for e in events)
    unique_files = set(e.get('fname', '') for e in events if e.get('fname'))
    features.append(len(unique_pids))
    features.append(len(unique_comms))
    features.append(len(unique_files))
    features.append(len(unique_pids) / max(1, n_events))
    features.append(len(unique_files) / max(1, n_events))
    
    # File path analysis (14-24)
    paths = [e.get('fname', '') for e in events if e.get('fname')]
    n_paths = len(paths)
    
    n_tmp = sum(1 for p in paths if '/tmp/' in p or '/var/tmp/' in p)
    n_hidden = sum(1 for p in paths if '/.' in p)
    n_system = sum(1 for p in paths if p.startswith('/usr/') or p.startswith('/etc/'))
    n_home = sum(1 for p in paths if '/home/' in p or p.startswith('~'))
    n_root = sum(1 for p in paths if p.startswith('/root/'))
    n_proc = sum(1 for p in paths if p.startswith('/proc/'))
    n_dev = sum(1 for p in paths if p.startswith('/dev/'))
    n_bin = sum(1 for p in paths if '/bin/' in p or '/sbin/' in p)
    n_lib = sum(1 for p in paths if '/lib/' in p)
    n_python = sum(1 for p in paths if 'site-packages' in p or '.py' in p)
    n_ssh = sum(1 for p in paths if 'ssh' in p.lower() or '.ssh/' in p)
    
    features.append(n_tmp)
    features.append(n_hidden)
    features.append(n_system)
    features.append(n_home)
    features.append(n_root)
    features.append(n_proc)
    features.append(n_dev)
    features.append(n_bin)
    features.append(n_lib)
    features.append(n_python)
    features.append(n_ssh)
    
    # Network activity (25-27)
    n_connects = event_types.get('connect', 0)
    features.append(n_connects)
    features.append(int(n_connects > 0))
    features.append(n_connects / max(1, n_events))
    
    # Suspicious commands (28-35)
    comms = [e.get('comm', '') for e in events]
    all_comms = ' '.join(comms).lower()
    
    curl_wget = sum(1 for c in comms if 'curl' in c.lower() or 'wget' in c.lower())
    nc_ncat = sum(1 for c in comms if c.lower() in ['nc', 'ncat', 'netcat'])
    shell = sum(1 for c in comms if c.lower() in ['bash', 'sh', 'zsh', 'ksh'])
    python = sum(1 for c in comms if 'python' in c.lower())
    node_ruby = sum(1 for c in comms if c.lower() in ['node', 'ruby', 'perl'])
    chmod_chown = sum(1 for c in comms if c.lower() in ['chmod', 'chown'])
    ssh_scp = sum(1 for c in comms if c.lower() in ['ssh', 'scp', 'sftp'])
    base64_openssl = sum(1 for c in comms if c.lower() in ['base64', 'openssl'])
    
    features.append(curl_wget)
    features.append(nc_ncat)
    features.append(shell)
    features.append(python)
    features.append(node_ruby)
    features.append(chmod_chown)
    features.append(ssh_scp)
    features.append(base64_openssl)
    
    # Time-based features (36-40)
    timestamps = [e.get('ts', 0) for e in events if e.get('ts')]
    if len(timestamps) > 1:
        timestamps_sorted = sorted(timestamps)
        duration = timestamps_sorted[-1] - timestamps_sorted[0]
        events_per_sec = n_events / max(1, duration / 1e9)
        
        # Time gaps
        gaps = [timestamps_sorted[i+1] - timestamps_sorted[i] for i in range(len(timestamps_sorted)-1)]
        avg_gap = np.mean(gaps) if gaps else 0
        max_gap = max(gaps) if gaps else 0
        min_gap = min(gaps) if gaps else 0
    else:
        duration = 0
        events_per_sec = 0
        avg_gap = 0
        max_gap = 0
        min_gap = 0
    
    features.append(np.log1p(duration))
    features.append(np.log1p(events_per_sec))
    features.append(np.log1p(avg_gap))
    features.append(np.log1p(max_gap))
    features.append(np.log1p(min_gap))
    
    # Package metadata patterns (41-45)
    # Look for encoded/obfuscated content patterns
    n_base64_like = sum(1 for p in paths if re.search(r'[A-Za-z0-9+/=]{40,}', p))
    n_url_like = sum(1 for p in paths if 'http' in p.lower() or '://' in p)
    
    # Deep file operations
    max_depth = max((p.count('/') for p in paths), default=0)
    avg_path_length = np.mean([len(p) for p in paths]) if paths else 0
    
    # Rapid file access pattern (many files in short time)
    unique_dirs = set('/'.join(p.split('/')[:-1]) for p in paths)
    features.append(n_base64_like)
    features.append(n_url_like)
    features.append(max_depth)
    features.append(avg_path_length)
    features.append(len(unique_dirs))
    
    return np.array(features, dtype=np.float32)


class HybridClassifierV2(nn.Module):
    """Enhanced hybrid model with more features and deeper architecture."""
    
    def __init__(self, num_nodes=50000, embedding_dim=128, stat_dim=45):
        super().__init__()
        self.tgn = TGNEncoder(num_nodes=num_nodes, out_dim=embedding_dim)
        
        # Enhanced statistical feature encoder
        self.stat_encoder = nn.Sequential(
            nn.Linear(stat_dim, 64),
            nn.LayerNorm(64),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(64, 64),
            nn.LayerNorm(64),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(64, 64),
            nn.LayerNorm(64),
            nn.GELU(),
        )
        
        # Deep classifier with residual
        combined_dim = embedding_dim + 64
        self.fc1 = nn.Linear(combined_dim, 128)
        self.ln1 = nn.LayerNorm(128)
        self.fc2 = nn.Linear(128, 128)
        self.ln2 = nn.LayerNorm(128)
        self.fc3 = nn.Linear(128, 64)
        self.ln3 = nn.LayerNorm(64)
        self.fc_out = nn.Linear(64, 1)
        
        self.dropout1 = nn.Dropout(0.4)
        self.dropout2 = nn.Dropout(0.3)
        self.dropout3 = nn.Dropout(0.2)
        
        # Initialize output layer
        nn.init.zeros_(self.fc_out.bias)
        nn.init.xavier_uniform_(self.fc_out.weight, gain=0.1)
    
    def forward(self, events):
        # TGN embedding
        self.tgn.memory_bank.reset_memory()
        constructor = ITBGConstructor(self.tgn)
        tgn_emb = constructor.replay_session(events)
        
        if tgn_emb is None:
            return None, None
        
        # Statistical features with normalization
        stat_features = extract_features_v2(events)
        stat_tensor = torch.from_numpy(stat_features)
        # Robust normalization
        stat_tensor = torch.log1p(torch.abs(stat_tensor)) * torch.sign(stat_tensor)
        stat_tensor = (stat_tensor - stat_tensor.mean()) / (stat_tensor.std() + 1e-6)
        
        # Encode stats
        stat_emb = self.stat_encoder(stat_tensor)
        
        # Combine
        combined = torch.cat([tgn_emb, stat_emb], dim=-1)
        
        # Deep classifier with residual
        h1 = F.gelu(self.ln1(self.fc1(combined)))
        h1 = self.dropout1(h1)
        
        h2 = F.gelu(self.ln2(self.fc2(h1)))
        h2 = self.dropout2(h2)
        h2 = h2 + h1  # Residual connection
        
        h3 = F.gelu(self.ln3(self.fc3(h2)))
        h3 = self.dropout3(h3)
        
        logits = self.fc_out(h3)
        
        return combined, logits


class FocalBCELoss(nn.Module):
    """Focal loss with class weighting for hard examples."""
    
    def __init__(self, pos_weight=1.0, alpha=0.25, gamma=2.0):
        super().__init__()
        self.pos_weight = torch.tensor(pos_weight)
        self.alpha = alpha
        self.gamma = gamma
    
    def forward(self, logits, targets):
        # Weighted BCE
        bce = F.binary_cross_entropy_with_logits(
            logits, targets, pos_weight=self.pos_weight, reduction='none'
        )
        
        # Focal weighting
        probs = torch.sigmoid(logits)
        p_t = probs * targets + (1 - probs) * (1 - targets)
        focal_weight = (1 - p_t) ** self.gamma
        
        return (focal_weight * bce).mean()


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
        except:
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
    LEARNING_RATE = 3e-4
    EPOCHS = 40  # Increased
    PATIENCE = 8  # Increased
    NUM_NODES = 50000
    CHECKPOINT_DIR = "models/checkpoints"
    
    set_seed(SEED)
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    
    print("Loading data...")
    clean_paths = glob.glob("data/zenodo_13746167/benign/traces/*.jsonl")
    mal_paths = glob.glob("data/zenodo_13746167/malware/traces/*.jsonl")
    
    print(f"Benign: {len(clean_paths)}")
    print(f"Malware: {len(mal_paths)}")
    
    train_set, val_set, test_set = split_data(
        clean_paths, mal_paths, TRAIN_RATIO, VAL_RATIO, TEST_RATIO, seed=SEED
    )
    
    print(f"\nSplits: Train={len(train_set)}, Val={len(val_set)}, Test={len(test_set)}")
    
    # Initialize V2 model
    print("\nInitializing HYBRID V2 model (45 features + deeper classifier)...")
    model = HybridClassifierV2(num_nodes=NUM_NODES)
    
    # Count parameters
    n_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Total trainable parameters: {n_params:,}")
    
    # Optimizer with weight decay
    optimizer = torch.optim.AdamW(
        model.parameters(), 
        lr=LEARNING_RATE, 
        weight_decay=1e-4
    )
    
    # Cosine annealing scheduler
    scheduler = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(
        optimizer, T_0=10, T_mult=2
    )
    
    # Focal loss with class weighting
    n_clean = sum(1 for _, l in train_set if l == 0)
    n_mal = sum(1 for _, l in train_set if l == 1)
    pos_weight = n_clean / max(1, n_mal)
    print(f"Using pos_weight={pos_weight:.2f}")
    loss_fn = FocalBCELoss(pos_weight=pos_weight, alpha=0.25, gamma=2.0)
    
    print(f"\nTraining (max {EPOCHS} epochs, patience={PATIENCE})")
    print("=" * 80)
    
    best_val_f1 = 0
    best_val_metrics = None
    epochs_without_improvement = 0
    
    for epoch in range(EPOCHS):
        train_metrics = train_epoch(model, optimizer, loss_fn, train_set)
        val_metrics = evaluate(model, loss_fn, val_set)
        scheduler.step()
        
        current_lr = optimizer.param_groups[0]['lr']
        
        print(f"\nEpoch {epoch + 1}/{EPOCHS} (lr={current_lr:.2e})")
        print(f"  Train: loss={train_metrics['loss']:.4f}, acc={train_metrics['accuracy']:.2%}, "
              f"recall={train_metrics['recall']:.2%}, f1={train_metrics['f1']:.2%}")
        print(f"  Val:   loss={val_metrics['loss']:.4f}, acc={val_metrics['accuracy']:.2%}, "
              f"prec={val_metrics['precision']:.2%}, recall={val_metrics['recall']:.2%}, "
              f"f1={val_metrics['f1']:.2%}")
        
        current_f1 = val_metrics['f1']
        if current_f1 > best_val_f1:
            best_val_f1 = current_f1
            best_val_metrics = val_metrics
            epochs_without_improvement = 0
            
            best_path = os.path.join(CHECKPOINT_DIR, "hybrid_v2_best.pt")
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
    best_checkpoint = torch.load(os.path.join(CHECKPOINT_DIR, "hybrid_v2_best.pt"))
    model.load_state_dict(best_checkpoint['model_state_dict'])
    
    # Test with multiple thresholds to find best
    print("\nSearching optimal threshold on validation set...")
    val_metrics = evaluate(model, loss_fn, val_set)
    
    # Find best threshold on validation
    best_thresh = 0.5
    best_val_f1_thresh = 0
    for t in np.arange(0.3, 0.8, 0.05):
        model.eval()
        all_logits = []
        all_labels = []
        with torch.no_grad():
            for path, label in val_set:
                try:
                    events = load_events(path)
                    _, logits = model(events)
                    if logits is not None:
                        all_logits.append(logits.squeeze())
                        all_labels.append(float(label))
                except:
                    continue
        
        if len(all_logits) > 0:
            logits = torch.stack(all_logits)
            labels = torch.tensor(all_labels)
            m = compute_metrics(logits, labels, threshold=t)
            if m['f1'] > best_val_f1_thresh:
                best_val_f1_thresh = m['f1']
                best_thresh = t
    
    print(f"Best validation threshold: {best_thresh:.2f} (F1={best_val_f1_thresh:.2%})")
    
    # Evaluate on test with best threshold
    model.eval()
    all_logits = []
    all_labels = []
    with torch.no_grad():
        for path, label in test_set:
            try:
                events = load_events(path)
                _, logits = model(events)
                if logits is not None:
                    all_logits.append(logits.squeeze())
                    all_labels.append(float(label))
            except:
                continue
    
    logits = torch.stack(all_logits)
    labels = torch.tensor(all_labels)
    test_metrics = compute_metrics(logits, labels, threshold=best_thresh)
    
    print("\n" + "=" * 80)
    print(f"FINAL TEST RESULTS (Hybrid V2, threshold={best_thresh:.2f})")
    print("=" * 80)
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
    
    torch.save(model.state_dict(), "models/scbf_hybrid_v2.pt")
    print(f"\nModel saved to: models/scbf_hybrid_v2.pt")
    print(f"Best threshold: {best_thresh:.2f}")


if __name__ == "__main__":
    main()
