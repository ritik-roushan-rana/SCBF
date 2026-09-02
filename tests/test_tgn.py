# test_tgn.py
import torch
from tgn_encoder import TGNEncoder

model = TGNEncoder(num_nodes=1000)
edge_feat = torch.randn(32)
dna = model.step(src=0, dst=1, t=torch.tensor(1000.0), edge_feat=edge_feat)
print(dna.shape)  # should be torch.Size([128])
