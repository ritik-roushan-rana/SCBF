"""
Training script with proper train/validation/test split for SCBF.

This script implements:
- 70/15/15 train/validation/test split
- Validation-based early stopping
- Test set evaluation after training
- Reproducible splits with random seed
"""

import torch
import glob
import json
import random
import os
import numpy as np
from datetime import datetime
from pathlib import Path

# Import from parent package
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.tgn_encoder import TGNEncoder
from models.itbg_constructor import ITBGConstructor


def set_seed(seed=42):
    """Set random seed for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def load_events(path):
    """Load events from JSONL file."""
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]


def split_data(clean_paths, mal_paths, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=42):
    """
    Split data into train/validation/test sets with stratification.
    
    Args:
        clean_paths: List of paths to clean package data
        mal_paths: List of paths to malicious package data
        train_ratio: Proportion for training (default: 0.7)
        val_ratio: Proportion for validation (default: 0.15)
        test_ratio: Proportion for test (default: 0.15)
        seed: Random seed for reproducibility
    
    Returns:
        train_set, val_set, test_set: Each is a list of (path, label) tuples
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6, \
        "Ratios must sum to 1.0"
    
    set_seed(seed)
    
    # Shuffle separately to maintain class balance
    clean_shuffled = clean_paths.copy()
    mal_shuffled = mal_paths.copy()
    random.shuffle(clean_shuffled)
    random.shuffle(mal_shuffled)
    
    # Calculate split indices for each class
    n_clean = len(clean_shuffled)
    n_mal = len(mal_shuffled)
    
    clean_train_end = int(n_clean * train_ratio)
    clean_val_end = int(n_clean * (train_ratio + val_ratio))
    
    mal_train_end = int(n_mal * train_ratio)
    mal_val_end = int(n_mal * (train_ratio + val_ratio))
    
    # Split clean data
    clean_train = [(p, 0) for p in clean_shuffled[:clean_train_end]]
    clean_val = [(p, 0) for p in clean_shuffled[clean_train_end:clean_val_end]]
    clean_test = [(p, 0) for p in clean_shuffled[clean_val_end:]]
    
    # Split malicious data
    mal_train = [(p, 1) for p in mal_shuffled[:mal_train_end]]
    mal_val = [(p, 1) for p in mal_shuffled[mal_train_end:mal_val_end]]
    mal_test = [(p, 1) for p in mal_shuffled[mal_val_end:]]
    
    # Combine and shuffle each set
    train_set = clean_train + mal_train
    val_set = clean_val + mal_val
    test_set = clean_test + mal_test
    
    random.shuffle(train_set)
    random.shuffle(val_set)
    random.shuffle(test_set)
    
    return train_set, val_set, test_set


def compute_embeddings(model, data_paths):
    """
    Compute DNA embeddings for a list of data paths.
    
    Args:
        model: TGNEncoder model
        data_paths: List of (path, label) tuples
    
    Returns:
        embeddings: Tensor of shape (N, embedding_dim)
        labels: Tensor of shape (N,)
    """
    dna_batch, label_batch = [], []
    
    for path, label in data_paths:
        model.memory_bank.reset_memory()
        constructor = ITBGConstructor(model)
        
        try:
            events = load_events(path)
            dna = constructor.replay_session(events)
            
            if dna is not None:
                dna_batch.append(dna)
                label_batch.append(label)
        except Exception as e:
            print(f"  WARNING: Failed to process {path}: {e}")
            continue
    
    if len(dna_batch) == 0:
        return None, None
    
    embeddings = torch.stack(dna_batch)
    labels = torch.tensor(label_batch)
    
    return embeddings, labels


def compute_contrastive_loss(embeddings, labels, margin=0.8):
    """
    Compute improved contrastive loss with stronger separation.
    
    Uses three components:
    1. Compactness: Pull clean samples toward centroid
    2. Separation: Push malicious samples away from centroid  
    3. Inter-class margin: Ensure minimum distance between classes
    
    Loss = compactness + 3.0 * max(0, margin - sqrt(mal_dist)) + 2.0 * max(0, margin - gap)
    
    Args:
        embeddings: Tensor of shape (N, embedding_dim)
        labels: Tensor of shape (N,) with 0=clean, 1=malicious
        margin: Margin for contrastive loss
    
    Returns:
        loss: Scalar tensor
        metrics: Dict with loss components
    """
    clean_mask = labels == 0
    mal_mask = labels == 1
    
    loss = torch.tensor(0.0)
    metrics = {}
    
    # Compactness loss for clean samples
    if clean_mask.sum() > 1:
        clean_embeddings = embeddings[clean_mask]
        clean_centroid = clean_embeddings.mean(dim=0, keepdim=True)
        
        # Component 1: Compactness (L2 distance, not squared)
        compactness = torch.sqrt(((clean_embeddings - clean_centroid) ** 2).sum(dim=-1) + 1e-8).mean()
        loss = loss + compactness
        metrics['compactness'] = compactness.item()
        
        # Component 2: Push malicious away (much stronger weight)
        if mal_mask.sum() > 0:
            mal_embeddings = embeddings[mal_mask]
            mal_dist = torch.sqrt(((mal_embeddings - clean_centroid) ** 2).sum(dim=-1) + 1e-8)
            
            # Strong penalty for being too close (3x weight)
            margin_loss = torch.clamp(margin - mal_dist, min=0).mean()
            loss = loss + 3.0 * margin_loss
            
            metrics['margin_loss'] = margin_loss.item()
            metrics['avg_mal_dist'] = mal_dist.mean().item()
            
            # Component 3: Maximize gap between closest malicious and farthest clean
            max_clean_dist = torch.sqrt(((clean_embeddings - clean_centroid) ** 2).sum(dim=-1) + 1e-8).max()
            min_mal_dist = mal_dist.min()
            gap = min_mal_dist - max_clean_dist
            
            # Penalty if gap is too small (2x weight)
            gap_loss = torch.clamp(margin - gap, min=0)
            loss = loss + 2.0 * gap_loss
            
            metrics['gap'] = gap.item()
            metrics['gap_loss'] = gap_loss.item()
    else:
        metrics['compactness'] = 0.0
        metrics['margin_loss'] = 0.0
        metrics['gap'] = 0.0
        metrics['gap_loss'] = 0.0
    
    metrics['total_loss'] = loss.item()
    return loss, metrics


def evaluate(model, data_paths, margin=0.8):
    """
    Evaluate model on validation or test set.
    
    Args:
        model: TGNEncoder model
        data_paths: List of (path, label) tuples
        margin: Margin for contrastive loss
    
    Returns:
        metrics: Dict with evaluation metrics
    """
    model.eval()
    
    with torch.no_grad():
        embeddings, labels = compute_embeddings(model, data_paths)
        
        if embeddings is None:
            return {'loss': float('inf'), 'n_samples': 0}
        
        loss, loss_metrics = compute_contrastive_loss(embeddings, labels, margin)
        
        # Add sample counts
        clean_count = (labels == 0).sum().item()
        mal_count = (labels == 1).sum().item()
        
        metrics = {
            **loss_metrics,
            'n_samples': len(labels),
            'n_clean': clean_count,
            'n_malicious': mal_count
        }
    
    model.train()
    return metrics


def train_epoch(model, optimizer, train_set, margin=0.8):
    """
    Train for one epoch.
    
    Args:
        model: TGNEncoder model
        optimizer: PyTorch optimizer
        train_set: List of (path, label) tuples
        margin: Margin for contrastive loss
    
    Returns:
        metrics: Dict with training metrics
    """
    model.train()
    
    # Balance classes by oversampling minority class
    clean_samples = [x for x in train_set if x[1] == 0]
    mal_samples = [x for x in train_set if x[1] == 1]
    
    # Oversample minority class
    if len(clean_samples) > len(mal_samples):
        mal_samples = mal_samples * (len(clean_samples) // max(1, len(mal_samples)) + 1)
        mal_samples = mal_samples[:len(clean_samples)]
    
    balanced_set = clean_samples + mal_samples
    random.shuffle(balanced_set)
    
    # Compute embeddings
    embeddings, labels = compute_embeddings(model, balanced_set)
    
    if embeddings is None or len(embeddings) < 2:
        return {'loss': float('inf'), 'n_samples': 0}
    
    # Compute loss and backprop
    loss, metrics = compute_contrastive_loss(embeddings, labels, margin)
    
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
    
    # Add sample counts
    clean_count = (labels == 0).sum().item()
    mal_count = (labels == 1).sum().item()
    
    metrics.update({
        'n_samples': len(labels),
        'n_clean': clean_count,
        'n_malicious': mal_count
    })
    
    return metrics


def save_split_info(train_set, val_set, test_set, output_dir):
    """Save split information for reproducibility."""
    split_info = {
        'train': [{'path': p, 'label': l} for p, l in train_set],
        'val': [{'path': p, 'label': l} for p, l in val_set],
        'test': [{'path': p, 'label': l} for p, l in test_set],
        'train_size': len(train_set),
        'val_size': len(val_set),
        'test_size': len(test_set),
        'timestamp': datetime.now().isoformat()
    }
    
    output_path = os.path.join(output_dir, 'split_info.json')
    with open(output_path, 'w') as f:
        json.dump(split_info, f, indent=2)
    
    print(f"\nSplit information saved to: {output_path}")


def main():
    """Main training function with train/val/test split."""
    
    # Configuration
    SEED = 42
    TRAIN_RATIO = 0.7
    VAL_RATIO = 0.15
    TEST_RATIO = 0.15
    MARGIN = 3.0  # Increased from 2.0 - need even larger separation
    LEARNING_RATE = 5e-4  # Reduced from 1e-3 for more stable training
    EPOCHS = 60  # Increased from 40 - may need more time
    PATIENCE = 10  # Increased from 5 - be more patient
    NUM_NODES = 50000
    CHECKPOINT_DIR = "models/checkpoints"
    
    # Set random seed
    set_seed(SEED)
    
    # Create output directory
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    
    # Load data paths
    print("Loading data paths...")
    clean_paths = glob.glob("data/zenodo_13746167/benign/traces/*.jsonl")
    mal_paths = glob.glob("data/zenodo_13746167/malware/traces/*.jsonl")
    
    print(f"Found {len(clean_paths)} benign packages")
    print(f"Found {len(mal_paths)} malware packages")
    
    if len(clean_paths) == 0 or len(mal_paths) == 0:
        print("\nERROR: No data found!")
        print("Expected location: data/zenodo_13746167/*/traces/*.jsonl")
        print("\nPlace your individual trace files in:")
        print("  data/zenodo_13746167/benign/traces/")
        print("  data/zenodo_13746167/malware/traces/")
        print("\nSee docs/restructuring/SIMPLE_SETUP.md for details")
        return
    
    # Split data
    print(f"\nSplitting data (train={TRAIN_RATIO}, val={VAL_RATIO}, test={TEST_RATIO})...")
    train_set, val_set, test_set = split_data(
        clean_paths, mal_paths, 
        TRAIN_RATIO, VAL_RATIO, TEST_RATIO, 
        seed=SEED
    )
    
    print(f"\nDataset splits:")
    print(f"  Train: {len(train_set)} samples "
          f"({len([x for x in train_set if x[1]==0])} clean, "
          f"{len([x for x in train_set if x[1]==1])} malicious)")
    print(f"  Val:   {len(val_set)} samples "
          f"({len([x for x in val_set if x[1]==0])} clean, "
          f"{len([x for x in val_set if x[1]==1])} malicious)")
    print(f"  Test:  {len(test_set)} samples "
          f"({len([x for x in test_set if x[1]==0])} clean, "
          f"{len([x for x in test_set if x[1]==1])} malicious)")
    
    # Save split information
    save_split_info(train_set, val_set, test_set, CHECKPOINT_DIR)
    
    # Initialize model
    print("\nInitializing model...")
    model = TGNEncoder(num_nodes=NUM_NODES)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    
    # Training loop
    print(f"\nStarting training (max {EPOCHS} epochs, patience={PATIENCE})...")
    print("=" * 80)
    
    best_val_loss = float('inf')
    epochs_without_improvement = 0
    
    for epoch in range(EPOCHS):
        # Train
        train_metrics = train_epoch(model, optimizer, train_set, MARGIN)
        
        # Validate
        val_metrics = evaluate(model, val_set, MARGIN)
        
        # Print progress
        print(f"\nEpoch {epoch + 1}/{EPOCHS}")
        print(f"  Train Loss: {train_metrics['total_loss']:.4f} "
              f"(clean={train_metrics['n_clean']}, mal={train_metrics['n_malicious']})")
        print(f"  Val Loss:   {val_metrics['total_loss']:.4f} "
              f"(clean={val_metrics['n_clean']}, mal={val_metrics['n_malicious']})")
        
        if 'compactness' in val_metrics:
            print(f"  Val Compactness: {val_metrics['compactness']:.4f}")
        if 'avg_mal_dist' in val_metrics:
            print(f"  Val Mal Distance: {val_metrics['avg_mal_dist']:.4f}")
        
        # Save checkpoint
        checkpoint_path = os.path.join(CHECKPOINT_DIR, f"tgn_epoch{epoch + 1}.pt")
        torch.save({
            'epoch': epoch + 1,
            'model_state_dict': model.state_dict(),
            'optimizer_state_dict': optimizer.state_dict(),
            'train_loss': train_metrics['total_loss'],
            'val_loss': val_metrics['total_loss'],
        }, checkpoint_path)
        
        # Track best model
        current_val_loss = val_metrics['total_loss']
        if current_val_loss < best_val_loss:
            best_val_loss = current_val_loss
            epochs_without_improvement = 0
            
            best_model_path = os.path.join(CHECKPOINT_DIR, "tgn_best.pt")
            torch.save({
                'epoch': epoch + 1,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'train_loss': train_metrics['total_loss'],
                'val_loss': val_metrics['total_loss'],
            }, best_model_path)
            
            print(f"  ✓ New best model (val_loss={best_val_loss:.4f})")
        else:
            epochs_without_improvement += 1
            print(f"  No improvement ({epochs_without_improvement}/{PATIENCE})")
        
        # Early stopping
        if epochs_without_improvement >= PATIENCE:
            print(f"\nEarly stopping at epoch {epoch + 1} - no improvement for {PATIENCE} epochs")
            break
    
    # Load best model for final evaluation
    print("\n" + "=" * 80)
    print("Loading best model for test evaluation...")
    best_checkpoint = torch.load(os.path.join(CHECKPOINT_DIR, "tgn_best.pt"))
    model.load_state_dict(best_checkpoint['model_state_dict'])
    
    # Final test evaluation
    print("\nEvaluating on test set...")
    test_metrics = evaluate(model, test_set, MARGIN)
    
    print("\n" + "=" * 80)
    print("FINAL TEST RESULTS:")
    print("=" * 80)
    print(f"Test Loss: {test_metrics['total_loss']:.4f}")
    print(f"Test Samples: {test_metrics['n_samples']} "
          f"({test_metrics['n_clean']} clean, {test_metrics['n_malicious']} malicious)")
    if 'compactness' in test_metrics:
        print(f"Test Compactness: {test_metrics['compactness']:.4f}")
    if 'avg_mal_dist' in test_metrics:
        print(f"Test Malicious Distance: {test_metrics['avg_mal_dist']:.4f}")
    print("=" * 80)
    
    # Save final model with test metrics
    final_model_path = "models/tgn_v2_best.pt"
    torch.save(model.state_dict(), final_model_path)
    
    print(f"\nTraining complete!")
    print(f"Best model saved to: {final_model_path}")
    print(f"Best validation loss: {best_val_loss:.4f}")
    print(f"Test loss: {test_metrics['total_loss']:.4f}")
    print(f"Checkpoints saved in: {CHECKPOINT_DIR}/")


if __name__ == "__main__":
    main()
