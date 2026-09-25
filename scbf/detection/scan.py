"""
Scan an install trace and issue a verdict: ALLOW / WARN / BLOCK.

Two independent opinions are reported, and they are deliberately not merged
into a single opaque score:

  1. Envelope distance - how far this install's behavioural signature sits
     from the centroid of known-benign installs. Catches behaviour that is
     simply abnormal, including attacks the classifier never saw.
  2. Classifier probability - the trained hybrid TGN's own judgement.

A reviewer needs to know WHY a package was blocked, so the report also lists
the concrete behaviours that drove the verdict: spawned binaries, outbound
destinations, credential reads, writes outside the install target.

Usage:
    python3 -m scbf.detection.scan --trace path/to/trace.jsonl
    python3 -m scbf.detection.scan --batch data/traces/malware/traces --limit 20
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from scbf.features.statistical import extract_features
from scbf.graph.itbg import CREDENTIAL_HINTS, PERSISTENCE_HINTS
from scbf.training.train import HybridClassifier, load_events, SNAPSHOTS

SUSPICIOUS_BINS = {"curl", "wget", "nc", "ncat", "netcat", "base64", "chmod",
                   "sh", "bash", "zsh", "dash", "openssl", "crontab", "ssh", "scp"}


# Infrastructure every install touches. Reporting these as "suspicious"
# makes the explanation useless: pip fetches from the PyPI CDN on Fastly, and
# sudo/PAM reads /etc/shadow during the privilege drop. Both appear in 100% of
# benign installs, so neither is evidence of anything.
REGISTRY_CDN_PREFIXES = ("151.101.", "146.75.", "199.232.")   # Fastly / PyPI
BOOTSTRAP_COMMS = {"sudo", "unix_chkpwd", "lsb_release", "getopt", "cut",
                   "tr", "uname"}
BOOTSTRAP_CRED_PATHS = ("/etc/shadow", "/etc/passwd", "/etc/group")


def evidence(events) -> list:
    """Human-readable reasons, so a verdict can be reviewed rather than trusted.

    Only behaviour attributable to the PACKAGE is reported. Installer and
    sandbox infrastructure is excluded, because an explanation that fires
    identically on benign and malicious installs explains nothing."""
    out = []
    spawned, dests, creds, persists, writes_out = set(), set(), set(), set(), set()
    for e in events:
        fn = e.get("fname", "") or ""
        comm = (e.get("comm") or "").rsplit("/", 1)[-1]
        if comm in BOOTSTRAP_COMMS:
            continue
        if e.get("type") == "exec":
            tgt = (fn or comm).rsplit("/", 1)[-1]
            if tgt in SUSPICIOUS_BINS:
                spawned.add(tgt)
        elif e.get("type") == "connect":
            d, p = e.get("daddr"), e.get("dport")
            if d and not (d.startswith("127.") or d.startswith("10.")
                          or d.startswith("192.168.")
                          or d.startswith(REGISTRY_CDN_PREFIXES)):
                dests.add(f"{d}:{p}")
        if any(h in fn for h in CREDENTIAL_HINTS) and \
                not fn.startswith(BOOTSTRAP_CRED_PATHS):
            creds.add(fn)
        if e.get("write"):
            if any(h in fn for h in PERSISTENCE_HINTS):
                persists.add(fn)
            elif fn.startswith(("/home/", "/root/", "/etc/")) and "site-packages" not in fn:
                writes_out.add(fn)

    if spawned:
        out.append(f"spawned suspicious binaries: {', '.join(sorted(spawned)[:6])}")
    if dests:
        out.append(f"outbound connections to {len(dests)} external endpoint(s): "
                   f"{', '.join(sorted(dests)[:4])}")
    if creds:
        out.append(f"read {len(creds)} credential-shaped path(s): "
                   f"{', '.join(sorted(creds)[:3])}")
    if persists:
        out.append(f"WROTE to persistence location(s): {', '.join(sorted(persists)[:3])}")
    if writes_out:
        out.append(f"wrote {len(writes_out)} file(s) outside the install target")
    if not out:
        out.append("no suspicious indicator observed")
    return out


class Scanner:
    def __init__(self, models: Path):
        self.model = HybridClassifier()
        self.model.load_state_dict(torch.load(models / "scbf_hybrid.pt",
                                              map_location="cpu"))
        self.model.eval()
        self.thr = 0.5
        t = models / "threshold.json"
        if t.exists():
            self.thr = json.loads(t.read_text()).get("threshold", 0.5)
        self.env = None
        e = models / "envelope.json"
        if e.exists():
            self.env = json.loads(e.read_text())

    def scan(self, path) -> dict:
        events = load_events(path)
        if not events:
            return {"verdict": "ERROR", "reason": "empty trace"}

        with torch.no_grad():
            dna = self.model.itbg.replay(events, SNAPSHOTS)
            if dna is None:
                return {"verdict": "ERROR", "reason": "no graph events"}
            g = self.model.graph_proj(dna.flatten().unsqueeze(0))
            stats = torch.from_numpy(extract_features(events)).unsqueeze(0)
            stats = (stats - self.model.feat_mean) / (self.model.feat_std + 1e-6)
            s = self.model.stat_proj(torch.clamp(stats, -10, 10))
            fused = torch.cat([g, s], dim=1)
            prob = float(torch.sigmoid(self.model.head(fused).squeeze()))

        verdict, dist, score = "ALLOW", None, 0.0
        if self.env:
            c = np.array(self.env["fused"]["centroid"])
            dist = float(np.linalg.norm(fused.squeeze(0).numpy() - c))
            warn, block = self.env["fused"]["warn_threshold"], self.env["fused"]["block_threshold"]
            # 0 at the centroid, 75 at the BLOCK threshold, capped at 100
            score = min(100.0, 75.0 * dist / block) if block else 0.0
            if dist >= block:
                verdict = "BLOCK"
            elif dist >= warn:
                verdict = "WARN"

        # the classifier is an independent second opinion; it can escalate
        if prob > self.thr and verdict == "ALLOW":
            verdict = "WARN"
        if prob > self.thr and verdict == "WARN" and self.env and dist and \
                dist >= self.env["fused"]["warn_threshold"]:
            verdict = "BLOCK"

        return {"verdict": verdict, "classifier_probability": prob,
                "envelope_distance": dist, "threat_score": round(score, 1),
                "n_events": len(events), "evidence": evidence(events)}


def show(path, r):
    icon = {"BLOCK": "[BLOCK]", "WARN": "[WARN ]", "ALLOW": "[ALLOW]"}.get(r["verdict"], "[ERROR]")
    print(f"\n{icon}  {Path(path).name}")
    if r["verdict"] == "ERROR":
        print(f"         {r['reason']}")
        return
    print(f"         threat score        : {r['threat_score']}/100")
    print(f"         classifier p(malicious): {r['classifier_probability']:.4f}")
    if r["envelope_distance"] is not None:
        print(f"         envelope distance   : {r['envelope_distance']:.4f}")
    print(f"         events              : {r['n_events']}")
    for e in r["evidence"]:
        print(f"           - {e}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", type=Path)
    ap.add_argument("--batch", type=Path)
    ap.add_argument("--models", type=Path, default=Path("models"))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    sc = Scanner(args.models)
    if not sc.env:
        print("WARNING: no envelope.json — verdicts fall back to the classifier "
              "alone. Run `python3 -m scbf.envelope.build` first.\n")

    if args.trace:
        show(args.trace, sc.scan(args.trace))
    elif args.batch:
        files = sorted(Path(args.batch).glob("*.jsonl"))
        if args.limit:
            files = files[: args.limit]
        counts = {}
        for f in files:
            r = sc.scan(f)
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
            show(f, r)
        print(f"\n{'=' * 60}\nSummary over {len(files)} traces: "
              + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    else:
        ap.error("pass --trace or --batch")


if __name__ == "__main__":
    main()
