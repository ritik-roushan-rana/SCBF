"""
Train the hybrid model: TGN graph encoder + statistical features.

Protocol (fixed so results stay comparable and honest):
  - 70/15/15 split, stratified, seed 42, written to models/split_info.json
  - feature normalization fitted ONCE on train, reused for val/test
  - balanced batching so every batch contains malicious examples
  - class-weighted BCE
  - model selection on val F1 only; the threshold is tuned on val only
  - test is scored exactly once, at the end

The test split is never used for any decision. That is the difference
between a number you can publish and a number that evaporates when
someone else reruns your code.
"""

import argparse
import json
import os
import random
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

from scbf.features.statistical import extract_features, STAT_DIM
from scbf.graph.itbg import ITBGConstructor
from scbf.models.tgn_encoder import TGNEncoder

NUM_NODES = 50000
EMBED_DIM = 128
# Finer temporal resolution: the DNA trajectory is the signal, and 4
# checkpoints was too coarse to capture where in the install the
# suspicious behavior happens.
SNAPSHOTS = (0.125, 0.25, 0.375, 0.50, 0.625, 0.75, 0.875, 1.00)


def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def load_events(path):
    with open(path) as f:
        out = []
        for line in f:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


class HybridClassifier(nn.Module):
    """TGN DNA snapshots + statistical features -> malicious logit."""

    def __init__(self, num_nodes=NUM_NODES, embed_dim=EMBED_DIM,
                 stat_dim=STAT_DIM, feat_mean=None, feat_std=None):
        super().__init__()
        self.tgn = TGNEncoder(num_nodes=num_nodes, out_dim=embed_dim)
        self.itbg = ITBGConstructor(self.tgn)

        self.register_buffer("feat_mean",
                             torch.zeros(stat_dim) if feat_mean is None else feat_mean)
        self.register_buffer("feat_std",
                             torch.ones(stat_dim) if feat_std is None else feat_std)

        self.graph_proj = nn.Sequential(
            nn.Linear(embed_dim * len(SNAPSHOTS), 256), nn.LayerNorm(256), nn.GELU(),
            nn.Dropout(0.1), nn.Linear(256, 128), nn.LayerNorm(128), nn.GELU(),
        )
        self.stat_proj = nn.Sequential(
            nn.Linear(stat_dim, 128), nn.LayerNorm(128), nn.GELU(),
            nn.Dropout(0.1), nn.Linear(128, 64), nn.LayerNorm(64), nn.GELU(),
        )
        self.head = nn.Sequential(
            nn.Linear(192, 64), nn.GELU(), nn.Dropout(0.2), nn.Linear(64, 1),
        )

    def forward(self, events):
        dna = self.itbg.replay(events, SNAPSHOTS)
        if dna is None:
            return None
        g = self.graph_proj(dna.flatten().unsqueeze(0))

        stats = torch.from_numpy(extract_features(events)).unsqueeze(0)
        stats = (stats - self.feat_mean) / (self.feat_std + 1e-6)
        stats = torch.clamp(stats, -10, 10)
        s = self.stat_proj(stats)

        return self.head(torch.cat([g, s], dim=1)).squeeze(-1)


def discover(traces_root: Path):
    """Usable traces only. Globbing would include FAILED installs, whose
    failure rate is class-correlated -- see scbf/dataset.py."""
    from scbf.dataset import ok_traces, dataset_summary
    items = ok_traces(traces_root)
    print(f"Dataset: {dataset_summary(traces_root)}")
    return items


def split_data(items, seed=42, ratios=(0.7, 0.15, 0.15)):
    """Stratified split, so class balance is identical across splits."""
    rng = random.Random(seed)
    by_class = {0: [], 1: []}
    for it in items:
        by_class[it["label"]].append(it)

    train, val, test = [], [], []
    for label, group in by_class.items():
        g = sorted(group, key=lambda d: d["path"])
        rng.shuffle(g)
        n = len(g)
        a, b = int(n * ratios[0]), int(n * (ratios[0] + ratios[1]))
        train += g[:a]
        val += g[a:b]
        test += g[b:]
    rng.shuffle(train); rng.shuffle(val); rng.shuffle(test)
    return train, val, test


def feature_stats(items):
    mat = []
    for it in items:
        ev = load_events(it["path"])
        if ev:
            mat.append(extract_features(ev))
    mat = np.array(mat)
    return (torch.tensor(mat.mean(0), dtype=torch.float32),
            torch.tensor(mat.std(0) + 1e-6, dtype=torch.float32))


def balanced_batches(items, batch_size=16, seed=0):
    """Every batch gets malicious examples regardless of overall imbalance."""
    rng = random.Random(seed)
    mal = [i for i in items if i["label"] == 1]
    ben = [i for i in items if i["label"] == 0]
    rng.shuffle(mal); rng.shuffle(ben)
    n_mal = max(1, batch_size // 3)
    n_ben = batch_size - n_mal
    batches, mi, bi = [], 0, 0
    while bi < len(ben):
        b = [mal[(mi + k) % len(mal)] for k in range(n_mal)] if mal else []
        b += ben[bi:bi + n_ben]
        mi += n_mal; bi += n_ben
        rng.shuffle(b)
        batches.append(b)
    return batches


def run_split(model, items, loss_fn=None, optimizer=None):
    train_mode = optimizer is not None
    model.train() if train_mode else model.eval()
    logits, labels, total_loss = [], [], 0.0

    groups = balanced_batches(items) if train_mode else [items]
    for batch in groups:
        if train_mode:
            optimizer.zero_grad()
        bl, by = [], []
        for it in batch:
            ev = load_events(it["path"])
            if not ev:
                continue
            ctx = torch.enable_grad() if train_mode else torch.no_grad()
            with ctx:
                out = model(ev)
            if out is None:
                continue
            bl.append(out.squeeze())
            by.append(float(it["label"]))
        if not bl:
            continue
        lg = torch.stack(bl)
        y = torch.tensor(by)
        if train_mode:
            loss = loss_fn(lg, y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += float(loss.detach())
        logits.append(lg.detach())
        labels.append(y)

    if not logits:
        return torch.empty(0), torch.empty(0), 0.0
    return torch.cat(logits), torch.cat(labels), total_loss / max(1, len(groups))


def metrics(logits, labels, thr=0.5):
    p = torch.sigmoid(logits)
    pred = (p > thr).long()
    y = labels.long()
    tp = int(((pred == 1) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    tot = max(1, tp + tn + fp + fn)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    try:
        from sklearn.metrics import roc_auc_score
        auc = float(roc_auc_score(y.numpy(), p.numpy()))
    except Exception:
        auc = None
    return dict(n=tot, accuracy=(tp + tn) / tot, precision=prec, recall=rec,
                f1=f1, roc_auc=auc, tp=tp, fn=fn, fp=fp, tn=tn, threshold=thr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", type=Path, default=Path("data/traces"))
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--patience", type=int, default=14)
    ap.add_argument("--lr", type=float, default=3e-4)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=Path("models"))
    ap.add_argument("--pw-mult", type=float, default=1.0,
                    help="Multiply class pos_weight; >1 trades precision for recall.")
    args = ap.parse_args()

    set_seed(args.seed)
    args.out.mkdir(parents=True, exist_ok=True)

    items = discover(args.traces)
    if not items:
        raise SystemExit(f"No traces under {args.traces}")
    train, val, test = split_data(items, seed=args.seed)
    n_mal = sum(i["label"] for i in train)
    print(f"Traces: {len(items)}  (benign {sum(1 for i in items if not i['label'])}, "
          f"malicious {sum(i['label'] for i in items)})")
    print(f"Split : train={len(train)} val={len(val)} test={len(test)}")

    with open(args.out / "split_info.json", "w") as f:
        json.dump({"train": train, "val": val, "test": test,
                   "seed": args.seed}, f, indent=2)

    print("Fitting feature normalization on train only...")
    mean, std = feature_stats(train)

    model = HybridClassifier(feat_mean=mean, feat_std=std)
    print(f"Parameters: {sum(p.numel() for p in model.parameters() if p.requires_grad):,}")

    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(opt, T_0=10, T_mult=2)
    pos_weight = (len(train) - n_mal) / max(1, n_mal) * args.pw_mult
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(pos_weight))
    print(f"pos_weight={pos_weight:.2f}\n")

    best_f1, best_epoch, stale = 0.0, 0, 0
    ckpt = args.out / "hybrid_best.pt"

    for epoch in range(1, args.epochs + 1):
        tl, ty, loss = run_split(model, train, loss_fn, opt)
        vl, vy, _ = run_split(model, val)
        sched.step()
        tm, vm = metrics(tl, ty), metrics(vl, vy)
        print(f"Epoch {epoch}/{args.epochs}  loss={loss:.4f}  "
              f"train f1={tm['f1']:.2%}  val f1={vm['f1']:.2%} "
              f"(p={vm['precision']:.2%} r={vm['recall']:.2%})")

        if vm["f1"] > best_f1:
            best_f1, best_epoch, stale = vm["f1"], epoch, 0
            torch.save({"model_state_dict": model.state_dict(),
                        "val_metrics": vm, "epoch": epoch}, ckpt)
            print(f"  ✓ new best (val F1={best_f1:.2%})")
        else:
            stale += 1
            if stale >= args.patience:
                print(f"\nEarly stopping at epoch {epoch} (best was {best_epoch})")
                break

    model.load_state_dict(torch.load(ckpt, weights_only=False)["model_state_dict"])

    # Threshold tuned on VAL only.
    vl, vy, _ = run_split(model, val)
    thr = max(np.arange(0.20, 0.85, 0.05),
              key=lambda t: metrics(vl, vy, float(t))["f1"])
    print(f"\nThreshold tuned on val: {thr:.2f}")

    torch.save(model.state_dict(), args.out / "scbf_hybrid.pt")
    with open(args.out / "threshold.json", "w") as f:
        json.dump({"threshold": float(thr), "best_val_f1": best_f1}, f, indent=2)
    print(f"Model saved: {args.out / 'scbf_hybrid.pt'}")
    print("Next: make evaluate")


if __name__ == "__main__":
    main()
