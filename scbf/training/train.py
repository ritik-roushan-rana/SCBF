import torch, glob, json, random, os
from tgn_encoder import TGNEncoder
from itbg_constructor import ITBGConstructor

def load_events(path):
    return [json.loads(l) for l in open(path)]

clean_paths = [(p, 0) for p in glob.glob("data/clean/*.jsonl")]
mal_paths = [(p, 1) for p in glob.glob("data/malicious/*.jsonl")]
all_paths = clean_paths + mal_paths

print(f"Clean sessions: {len(clean_paths)}, Malicious sessions: {len(mal_paths)}")

model = TGNEncoder(num_nodes=50000)
optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

MARGIN = 0.8
EPOCHS = 25               # upper bound — early stopping will likely cut this short
PATIENCE = 5              # stop if no improvement for this many epochs
CHECKPOINT_DIR = "checkpoints"
os.makedirs(CHECKPOINT_DIR, exist_ok=True)

best_loss = float("inf")
epochs_without_improvement = 0

for epoch in range(EPOCHS):
    epoch_paths = clean_paths + mal_paths * max(1, len(clean_paths) // max(1, len(mal_paths)))
    random.shuffle(epoch_paths)

    dna_batch, label_batch = [], []
    for path, label in epoch_paths:
        model.memory_bank.reset_memory()
        constructor = ITBGConstructor(model)
        events = load_events(path)
        dna = constructor.replay_session(events)
        if dna is not None:
            dna_batch.append(dna)
            label_batch.append(label)

    if len(dna_batch) < 2:
        print(f"epoch {epoch}: not enough data, skipping")
        continue

    stacked = torch.stack(dna_batch)
    labels = torch.tensor(label_batch)
    clean_mask = labels == 0
    mal_mask = labels == 1

    loss = torch.tensor(0.0)

    if clean_mask.sum() > 1:
        clean_centroid = stacked[clean_mask].mean(dim=0, keepdim=True)
        compactness = ((stacked[clean_mask] - clean_centroid) ** 2).sum(dim=-1).mean()
        loss = loss + compactness

        if mal_mask.sum() > 0:
            mal_dist = ((stacked[mal_mask] - clean_centroid) ** 2).sum(dim=-1)
            margin_loss = torch.clamp(MARGIN - mal_dist, min=0).mean()
            loss = loss + margin_loss

    optimizer.zero_grad()
    loss.backward()
    optimizer.step()

    current_loss = loss.item()
    print(f"epoch {epoch} loss {current_loss:.4f} "
          f"(clean={clean_mask.sum().item()}, mal={mal_mask.sum().item()})")

    # --- Checkpointing: save every epoch, tagged with epoch number ---
    checkpoint_path = f"{CHECKPOINT_DIR}/tgn_epoch{epoch}.pt"
    torch.save(model.state_dict(), checkpoint_path)

    # --- Track and save the best model separately ---
    if current_loss < best_loss:
        best_loss = current_loss
        epochs_without_improvement = 0
        torch.save(model.state_dict(), "tgn_v2_best.pt")
        print(f"  -> new best (loss={best_loss:.4f}), saved to tgn_v2_best.pt")
    else:
        epochs_without_improvement += 1
        print(f"  -> no improvement ({epochs_without_improvement}/{PATIENCE})")

    # --- Early stopping ---
    if epochs_without_improvement >= PATIENCE:
        print(f"\nEarly stopping at epoch {epoch} — no improvement for {PATIENCE} epochs.")
        break

# Always save the final state too, for reference
torch.save(model.state_dict(), "tgn_v2_final.pt")
print(f"\nTraining complete. Best loss: {best_loss:.4f}")
print("Best model: tgn_v2_best.pt")
print("Final model: tgn_v2_final.pt")
print(f"Per-epoch checkpoints in: {CHECKPOINT_DIR}/")
