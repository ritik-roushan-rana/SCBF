import torch, glob, json, numpy as np
from tgn_encoder import TGNEncoder
from itbg_constructor import ITBGConstructor

model = TGNEncoder(num_nodes=50000)
model.load_state_dict(torch.load("tgn_v2.pt"))
model.eval()

vectors = []
with torch.no_grad():
    for path in glob.glob("data/clean/*.jsonl"):
        model.memory_bank.reset_memory()
        constructor = ITBGConstructor(model)
        events = [json.loads(l) for l in open(path)]
        dna = constructor.replay_session(events)
        if dna is not None:
            vectors.append(dna.numpy())

vectors = np.array(vectors)
centroid = vectors.mean(axis=0)
np.save("envelope_v2.npy", centroid)
print(f"Envelope v2 built from {len(vectors)} clean sessions")
