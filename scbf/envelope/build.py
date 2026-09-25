"""
Behavioural envelope: what a NORMAL install looks like.

Detection here is deviation from calibrated normality, not a match against a
catalogue of known-bad patterns. That is what lets an unseen, renamed or
typosquatted package be judged on behaviour alone.

Construction:
  1. Pass every benign TRAINING install through the trained encoder.
     (Training split only -- calibrating on val/test would leak.)
  2. Take the centroid of those signatures.
  3. Record the distribution of distances from that centroid.
  4. WARN  at mean + 1.5 sd
     BLOCK at mean + 2.5 sd

Two embodiments are stored, both usable:
    pure  - the 128-dim TGN signature alone
    fused - the 192-dim signature + projected statistical descriptors

Usage:
    python3 -m scbf.envelope.build --traces data/traces --models models
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from scbf.features.statistical import extract_features
from scbf.training.train import HybridClassifier, load_events, SNAPSHOTS


def signatures(model: HybridClassifier, items):
    """Return (pure 128-dim, fused 192-dim) signatures for each trace."""
    pure, fused = [], []
    with torch.no_grad():
        for it in items:
            ev = load_events(it["path"])
            if not ev:
                continue
            dna = model.itbg.replay(ev, SNAPSHOTS)
            if dna is None:
                continue
            g = model.graph_proj(dna.flatten().unsqueeze(0))

            stats = torch.from_numpy(extract_features(ev)).unsqueeze(0)
            stats = (stats - model.feat_mean) / (model.feat_std + 1e-6)
            s = model.stat_proj(torch.clamp(stats, -10, 10))

            pure.append(dna[-1].numpy())                       # final DNA vector
            fused.append(torch.cat([g, s], dim=1).squeeze(0).numpy())
    return np.array(pure), np.array(fused)


def envelope_from(sig: np.ndarray) -> dict:
    centroid = sig.mean(axis=0)
    d = np.linalg.norm(sig - centroid, axis=1)
    mean, sd = float(d.mean()), float(d.std())
    return {
        "centroid": centroid.tolist(),
        "dim": int(sig.shape[1]),
        "n_calibration": int(sig.shape[0]),
        "mean_distance": mean,
        "std_distance": sd,
        "warn_threshold": mean + 1.5 * sd,
        "block_threshold": mean + 2.5 * sd,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", type=Path, default=Path("data/traces"))
    ap.add_argument("--models", type=Path, default=Path("models"))
    args = ap.parse_args()

    split = json.loads((args.models / "split_info.json").read_text())
    benign_train = [i for i in split["train"] if i["label"] == 0]
    print(f"Calibrating on {len(benign_train)} benign TRAINING installs "
          f"(val/test excluded to avoid leakage)")

    model = HybridClassifier()
    model.load_state_dict(torch.load(args.models / "scbf_hybrid.pt",
                                     map_location="cpu"))
    model.eval()

    pure, fused = signatures(model, benign_train)
    print(f"  signatures: pure {pure.shape}, fused {fused.shape}")

    out = {"pure": envelope_from(pure), "fused": envelope_from(fused)}
    for name, e in out.items():
        print(f"\n{name} ({e['dim']}-dim, n={e['n_calibration']}):")
        print(f"  mean distance  = {e['mean_distance']:.4f}")
        print(f"  std  distance  = {e['std_distance']:.4f}")
        print(f"  WARN  >= {e['warn_threshold']:.4f}")
        print(f"  BLOCK >= {e['block_threshold']:.4f}")

    path = args.models / "envelope.json"
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nSaved: {path}")


if __name__ == "__main__":
    main()
