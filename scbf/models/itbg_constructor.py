import torch

class NodeIDMap:
    def __init__(self):
        self.map = {}
        self.next_id = 0

    def get(self, key):
        if key not in self.map:
            self.map[key] = self.next_id
            self.next_id += 1
        return self.map[key]


CREDENTIAL_PATTERNS = ['/.ssh/', '/.aws/', '/.env', '/etc/passwd', '/etc/shadow']
NOISE_PATTERNS = ['/pip-unpack-', '/pip-metadata-', '/pip-install-', '/pip-ephem-wheel-cache-']
SNAPSHOT_FRACTIONS = [0.25, 0.50, 0.75, 1.00]


class ITBGConstructor:
    def __init__(self, tgn_encoder, edge_feat_dim=32):
        self.tgn = tgn_encoder
        self.node_ids = NodeIDMap()
        self.edge_feat_dim = edge_feat_dim
        self.dna_history = []
        self.last_dna = None

    def _edge_features(self, event):
        etype_map = {"exec": 0.0, "open": 1.0, "connect": 2.0,
                     "env_read": 3.0, "credential_read": 4.0}
        etype_val = etype_map.get(event.get("type", ""), -1.0)

        path = event.get("fname", "")
        is_credential = float(any(p in path for p in CREDENTIAL_PATTERNS))
        is_temp = float(path.startswith("/tmp") or path.startswith("/var/tmp"))
        is_pip_internal = float(any(p in path for p in NOISE_PATTERNS))
        is_site_packages = float("site-packages" in path or path.endswith(
            (".py", ".pyc", ".so")))
        path_len = min(len(path) / 200.0, 1.0)
        path_depth = min(path.count("/") / 20.0, 1.0)

        base = torch.tensor([
            etype_val, is_credential, is_temp,
            is_pip_internal, is_site_packages, path_len, path_depth,
        ], dtype=torch.float32)

        reps = (self.edge_feat_dim // base.shape[0]) + 1
        return base.repeat(reps)[:self.edge_feat_dim]

    def _is_noise(self, event):
        path = event.get("fname", "")
        return any(p in path for p in NOISE_PATTERNS) or "__pycache__" in path \
            or path.endswith(".dist-info") or "/test cases/" in path \
            or "/tests/" in path or "LICENSES" in path

    def add_event(self, event):
        if self._is_noise(event):
            return None

        if event["type"] == "exec":
            src = self.node_ids.get(f"proc:{event.get('ppid', 0)}")
            dst = self.node_ids.get(f"proc:{event.get('pid', 0)}")
        elif event["type"] == "open":
            src = self.node_ids.get(f"proc:{event.get('pid', 0)}")
            dst = self.node_ids.get(f"file:{event.get('fname', '')}")
        else:
            return None

        edge_feat = self._edge_features(event)
        t = torch.tensor(float(event["ts"]))
        dna = self.tgn.step(src, dst, t, edge_feat)

        self.dna_history.append(dna.detach())
        self.last_dna = dna
        return dna

    def replay_session(self, events):
        """Stage-aware replay: process the FULL event stream (no subsampling
        of which events happen — every event still updates memory), but only
        record snapshots of the DNA vector at fixed relative checkpoints
        (25/50/75/100% through the stream). This removes the dependency on
        raw event count from the final representation, matching the original
        design's 'Behavioral Envelope Profile per install-stage' approach."""
        self.dna_history = []
        self.last_dna = None

        sorted_events = sorted(events, key=lambda x: x["ts"])
        total = len(sorted_events)
        if total == 0:
            return None

        # Precompute the event indices corresponding to each snapshot fraction
        checkpoint_indices = {int(total * f) - 1 for f in SNAPSHOT_FRACTIONS if int(total * f) > 0}
        checkpoint_indices.add(total - 1)  # always include the true final event

        snapshots = []
        for i, e in enumerate(sorted_events):
            dna = self.add_event(e)
            if i in checkpoint_indices and dna is not None:
                snapshots.append(dna)

        if not snapshots:
            # fall back to last live dna if all checkpointed events were noise-filtered
            return self.last_dna

        # Average the fixed-count stage snapshots — same number of data points
        # (at most 4) regardless of whether the package had 1,200 or 7,500 events.
        return torch.stack(snapshots).mean(dim=0)
