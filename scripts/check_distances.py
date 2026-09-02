import glob, json,numpy as np,torch
from tgn_encoder import TGNEncoder
from itbg_constructor import ITBGConstructor
model = TGNEncoder(num_nodes=50000)
model.load_state_dict(torch.load("tgn_v1.pt"))
model.eval()
centroid = np.load("envelope_pure_python.npy")
for path in glob.glob("data/clean/*.jsonl"):
	model.memory_bank.reset_memory()
	constructor = ITBGConstructor(model)
	events =[json.loads(l) for l in open(path)]
	dna = constructor.replay_session(events)
	if dna is not None:
		dist = np.linalg.norm(dna.detach().numpy()-centroid)
		print(f"{path}: {dist:.4f}")

