import torch, glob, json, random
from tgn_encoder import TGNEncoder
from itbg_constructor import ITBGConstructor

def load_events(path):
    return [json.loads(l) for l in open(path)]

clean_paths = glob.glob("data/clean/*.jsonl")
print(f"[debug] found {len(clean_paths)} files in data/clean/: {clean_paths}")

model = TGNEncoder(num_nodes=50000)
optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

EPOCHS = 3  # just enough to confirm, not full 10
for epoch in range(EPOCHS):
    random.shuffle(clean_paths)
    total_loss = 0.0
    all_dna = []

    for path in clean_paths:
        model.memory_bank.reset_memory()
        constructor = ITBGConstructor(model)
        events = load_events(path)
        final_dna = constructor.replay_session(events)

        # per-session diagnostics
        n_events = len(events)
        n_processed = len(constructor.dna_history)  # events that survived _is_noise + type check
        print(f"[debug] {path}: {n_events} raw events, {n_processed} passed filter, "
              f"final_dna is {'None' if final_dna is None else 'OK'}")

        if final_dna is not None:
            all_dna.append(final_dna)

    print(f"[debug] epoch {epoch}: all_dna length = {len(all_dna)}")

    if len(all_dna) > 1:
        stacked = torch.stack(all_dna)
        centroid = stacked.mean(dim=0, keepdim=True)
        loss = ((stacked - centroid) ** 2).sum(dim=-1).mean()

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        total_loss = loss.item()

    print(f"epoch {epoch} loss {total_loss:.4f}")
