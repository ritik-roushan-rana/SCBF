"""
Early-blocking analysis: can we terminate the installer BEFORE the payload acts?

The post-install classifier answers "was this package malicious". A prevention
mechanism has to answer a harder question: "at which event does it become
justified to kill the process tree, and does that moment arrive before the
damaging action rather than after it".

Four things are measured, per malicious trace:

  1. FIRST HIGH-RISK EVENT  - the index of the first genuinely damaging action:
     an outbound connection to non-registry infrastructure, a shell or
     downloader spawn, a credential-shaped read, or a write to a persistence
     location. This is the deadline. Blocking after it is too late.

  2. FIRST MODEL ALARM      - the earliest checkpoint at which the staged
     envelope score crosses its BLOCK threshold.

  3. PREVENTED or NOT       - whether (2) happens strictly before (1).

  4. FALSE POSITIVES        - the same policy applied to benign installs.

A rule-based tripwire (block immediately on the first high-risk event) is
evaluated alongside, because if a one-line rule prevents more damage than the
model does, that is the honest finding and the model should not be claimed as a
prevention mechanism.

Usage:
    python3 -m scbf.detection.early --models models --n 25
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from scbf.envelope.streaming import partial_signature
from scbf.training.train import HybridClassifier, load_events

CDN = ("151.101.", "146.75.", "199.232.")
BOOTSTRAP_COMMS = {"sudo", "unix_chkpwd", "lsb_release", "getopt", "cut", "tr", "uname"}
RISKY_BINS = {"curl", "wget", "nc", "ncat", "netcat", "base64", "chmod", "chown",
              "sh", "bash", "zsh", "dash", "openssl", "crontab", "ssh", "scp", "nohup"}
CRED = ("/.ssh/", "/.aws/", "/.netrc", "/.git-credentials", "/.pypirc",
        "/.npmrc", "/.docker/config", "/.kube/config")
PERSIST = ("/.bashrc", "/.bash_profile", "/.zshrc", "/.profile", "/etc/cron",
           "/.ssh/authorized_keys", "/etc/systemd", "/.config/autostart")

# Dense early checkpoints: prevention is only meaningful in the first events.
EARLY_CHECKPOINTS = (100, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 4000, 6000)


def first_high_risk(events):
    """(index, description) of the first genuinely damaging action, or None."""
    for i, e in enumerate(events):
        comm = (e.get("comm") or "").rsplit("/", 1)[-1]
        if comm in BOOTSTRAP_COMMS:
            continue
        fn = e.get("fname", "") or ""
        t = e.get("type")
        if t == "exec":
            tgt = (fn or comm).rsplit("/", 1)[-1]
            if tgt in RISKY_BINS:
                return i, f"spawned {tgt}"
        if t == "connect":
            d = e.get("daddr") or ""
            if d and not d.startswith(("127.", "10.", "192.168.")) and not d.startswith(CDN):
                return i, f"connect {d}:{e.get('dport')}"
        if any(h in fn for h in CRED):
            return i, f"read {fn}"
        if e.get("write") and any(h in fn for h in PERSIST):
            return i, f"WROTE {fn}"
    return None


def first_alarm(model, events, stages):
    """(event_index, distance) of the earliest checkpoint crossing BLOCK."""
    with torch.no_grad():
        for c in sorted(int(k) for k in stages):
            if c > len(events):
                break                      # only genuine mid-install points
            st = stages[str(c)]
            sig = partial_signature(model, events, c)
            if sig is None:
                continue
            d = float(np.linalg.norm(sig - np.array(st["centroid"])))
            if d >= st["block_threshold"]:
                return c, d
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", type=Path, default=Path("models"))
    ap.add_argument("--n", type=int, default=25)
    args = ap.parse_args()

    model = HybridClassifier()
    model.load_state_dict(torch.load(args.models / "scbf_hybrid.pt", map_location="cpu"))
    model.eval()
    stages = json.loads((args.models / "envelope_streaming.json").read_text())["stages"]
    split = json.loads((args.models / "split_info.json").read_text())

    print("=" * 96)
    print("EARLY BLOCKING — can the installer be killed before the payload acts?")
    print("=" * 96)

    mal = [i for i in split["test"] if i["label"] == 1][: args.n]
    print(f"\n{'package':<28}{'events':>7}{'1st high-risk':>26}{'model alarm':>14}{'result':>18}")
    print("-" * 96)

    n_risky = n_prevented = n_late = n_alarm = 0
    rows = []
    for it in mal:
        ev = load_events(it["path"])
        if not ev:
            continue
        hr = first_high_risk(ev)
        al = first_alarm(model, ev, stages)
        name = Path(it["path"]).stem[:26]
        hr_s = f"ev {hr[0]} ({hr[0]/len(ev):.0%}) {hr[1][:12]}" if hr else "none"
        al_s = f"ev {al[0]}" if al else "never"
        if hr:
            n_risky += 1
            if al and al[0] < hr[0]:
                res, n_prevented = "PREVENTED", n_prevented + 1
            else:
                res, n_late = "too late", n_late + 1
        else:
            res = "no risky action"
        if al:
            n_alarm += 1
        print(f"{name:<28}{len(ev):>7}{hr_s:>26}{al_s:>14}{res:>18}")
        rows.append((hr, al, len(ev)))

    ben = [i for i in split["test"] if i["label"] == 0][: args.n]
    fp_model = fp_rule = 0
    for it in ben:
        ev = load_events(it["path"])
        if not ev:
            continue
        if first_alarm(model, ev, stages):
            fp_model += 1
        if first_high_risk(ev):
            fp_rule += 1

    n = len(rows)
    print("\n" + "=" * 96)
    print("ANSWERS")
    print("=" * 96)
    print(f"\n1. Malicious samples analysed                     : {n}")
    print(f"   with any high-risk action at all                : {n_risky} ({n_risky/max(1,n):.0%})")
    print(f"   with NO high-risk action (nothing to prevent)   : {n - n_risky} ({(n-n_risky)/max(1,n):.0%})")

    print(f"\n2. Model alarm fires before the high-risk action   : {n_prevented}/{n_risky}"
          f" ({n_prevented/max(1,n_risky):.0%} of those with an action)")
    print(f"   Fires only after the damage is done             : {n_late}/{n_risky}")

    print(f"\n3. Blocked at any genuine mid-install point        : {n_alarm}/{n} ({n_alarm/max(1,n):.0%})")

    print(f"\n4. FALSE POSITIVES on benign installs")
    print(f"   model, same early policy                        : {fp_model}/{len(ben)} ({fp_model/max(1,len(ben)):.0%})")
    print(f"   rule-based tripwire (block on 1st risky action)  : {fp_rule}/{len(ben)} ({fp_rule/max(1,len(ben)):.0%})")

    print("\n" + "-" * 96)
    print("COMPARISON: model vs a one-line tripwire, as PREVENTION")
    print(f"  tripwire recall  : {n_risky}/{n} ({n_risky/max(1,n):.0%}) — blocks AT the risky action, by construction")
    print(f"  model prevention : {n_prevented}/{n} ({n_prevented/max(1,n):.0%}) — blocks BEFORE it")
    print(f"  tripwire FP      : {fp_rule/max(1,len(ben)):.0%}        model FP: {fp_model/max(1,len(ben)):.0%}")


if __name__ == "__main__":
    main()
