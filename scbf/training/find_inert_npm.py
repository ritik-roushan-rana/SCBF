"""
Identify install-inert traces in the RQ1 NPM dataset.

A trace is "install-inert" when nothing beyond npm's own bootstrap ran
during `npm install`:

    * no exec events
    * no connect() from a process other than npm's own network path
    * no process (comm) outside npm's baseline set
      {npm, node, libuv-worker, sudo, "npm install /ho"}
    * at most NODE_BASELINE_EVENTS events from `node` (npm's own bootstrap
      produces exactly 22 on the capture host; a lifecycle script always
      adds more)

For a *malicious* package this means the payload never executed at
install time (it fires on require(), or needs an environment the sandbox
did not provide). Such a trace is byte-for-byte a plain install and no
behavioral model can separate it from a benign one, so it is label noise
for the install-time detector.

Writes data/rq1_npm/install_inert.json with the inert malware and benign
trace names plus the rule used. The trainer's --exclude-inert flag reads
this file and drops the inert *malware* traces (benign inert traces are
genuine benign installs and are kept).

Usage:
    python -m scbf.training.find_inert_npm [DATA_DIR]      (default data/rq1_npm)
"""

import glob
import json
import os
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from scbf.training.train_npm_hybrid import DATA_DIR  # noqa: E402

DATA = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(DATA_DIR)   # e.g. data/rq1_npm_rich
INERT_FILE = PROJECT_ROOT / DATA / "install_inert.json"

BASELINE_COMMS = {"npm", "node", "libuv-worker", "sudo", "npm install /ho"}
NPM_NET_COMMS = {"npm", "node", "libuv-worker", "git-remote-http", "sudo", "npm install /ho"}
NODE_BASELINE_EVENTS = 22


def activity_signature(path):
    comms = Counter()
    n_exec = n_foreign_connect = 0
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            comms[e.get("comm", "")] += 1
            if e.get("type") == "exec":
                n_exec += 1
            elif e.get("type") == "connect" and e.get("comm", "") not in NPM_NET_COMMS:
                n_foreign_connect += 1
    return {
        "n_events": sum(comms.values()),
        "n_exec": n_exec,
        "n_foreign_connect": n_foreign_connect,
        "node_events": comms.get("node", 0),
        "extra_comms": sorted(set(comms) - BASELINE_COMMS),
    }


def is_inert(sig):
    return (sig["n_exec"] == 0 and sig["n_foreign_connect"] == 0
            and not sig["extra_comms"] and sig["node_events"] <= NODE_BASELINE_EVENTS)


def main():
    out = {"rule": {
        "baseline_comms": sorted(BASELINE_COMMS),
        "npm_net_comms": sorted(NPM_NET_COMMS),
        "node_baseline_events": NODE_BASELINE_EVENTS,
    }}
    for name in ("benign", "malware"):
        paths = sorted(glob.glob(str(PROJECT_ROOT / DATA / name / "traces" / "*.jsonl")))
        inert, active = [], []
        for p in paths:
            (inert if is_inert(activity_signature(p)) else active).append(os.path.basename(p))
        out[name] = {"total": len(paths), "inert": inert, "n_inert": len(inert), "n_active": len(active)}
        print(f"{name:8}: {len(paths)} traces, {len(inert)} install-inert ({len(inert) / max(1, len(paths)):.1%})")

    INERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(INERT_FILE, "w") as f:
        json.dump(out, f, indent=1)
    print(f"\nSaved -> {INERT_FILE}")
    print("\nInert malware (payload did not run at install time):")
    for name in out["malware"]["inert"]:
        print(f"  {name}")


if __name__ == "__main__":
    main()
