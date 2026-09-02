# tgn_encoder.py
import torch, torch.nn as nn

class TimeEncode(nn.Module):
    def __init__(self, dim):
        super().__init__()
        self.w = nn.Linear(1, dim)

    def forward(self, delta_t):
        delta_t = delta_t.float() / 1e9
        return torch.cos(self.w(delta_t.unsqueeze(-1)))


class TGNMemory(nn.Module):
    def __init__(self, num_nodes, memory_dim=64, edge_feat_dim=32, time_dim=16):
        super().__init__()
        self.memory_dim = memory_dim
        self.time_encoder = TimeEncode(time_dim)
        self.gru = nn.GRUCell(memory_dim + edge_feat_dim + time_dim, memory_dim)
        self.reset_memory()

    def reset_memory(self):
        """Call this at the START of every install session (not mid-session).
        Using a plain dict (not a buffer) keeps tensors in the autograd graph."""
        self.memory = {}
        self.last_update = {}

    def _get(self, node_id):
        if node_id not in self.memory:
            self.memory[node_id] = torch.zeros(self.memory_dim)
            self.last_update[node_id] = torch.tensor(0.0)
        return self.memory[node_id]

    def compute_message(self, src, dst, t, edge_feat):
        mem_src = self._get(src)
        delta_t = t - self.last_update[src]
        t_enc = self.time_encoder(delta_t.unsqueeze(0)).squeeze(0)
        return torch.cat([mem_src, edge_feat, t_enc], dim=-1)

    def update(self, node_id, message, t):
        mem_dst = self._get(node_id)
        new_mem = self.gru(message.unsqueeze(0), mem_dst.unsqueeze(0)).squeeze(0)
        self.memory[node_id] = new_mem      # NOTE: no .detach() — keep it trainable
        self.last_update[node_id] = t
        return new_mem


class TGNEncoder(nn.Module):
    def __init__(self, num_nodes, memory_dim=64, edge_feat_dim=32, time_dim=16, out_dim=128):
        super().__init__()
        self.memory_bank = TGNMemory(num_nodes, memory_dim, edge_feat_dim, time_dim)
        self.proj = nn.Sequential(
            nn.Linear(memory_dim, out_dim),
            nn.LayerNorm(out_dim)
        )

    def step(self, src, dst, t, edge_feat):
        msg = self.memory_bank.compute_message(src, dst, t, edge_feat)
        new_mem = self.memory_bank.update(dst, msg, t)
        dna = self.proj(new_mem)
        return nn.functional.normalize(dna, dim=-1)
