"""
What is actually IN the traces, and what is the detection ceiling?

Two questions this answers before any model is trained:

  1. Did the monitor fix deliver usable signal? Count traces containing
     real exec chains, external network destinations, credential reads and
     persistence writes. In the v1 capture these were all ~zero, which is
     why the model fell back on a collection artifact.

  2. What is the maximum achievable recall? A large share of PyPI malware
     is Windows-targeted. The 1337z sample reads os.environ['COMPUTERNAME']
     inside a bare `except: pass`, so on Linux it raises KeyError and does
     nothing observable. Such a package is undetectable by ANY dynamic
     method -- there is no behavior to detect. Traces with no suspicious
     indicator at all put a hard ceiling on recall that no architecture
     can lift, and you need that number before interpreting a result.

Usage:
    python3 -m scbf.audit.signal_report --traces data/traces
"""

import argparse
import json
from collections import Counter
from pathlib import Path

SUSPICIOUS_BINS = {"curl", "wget", "nc", "ncat", "netcat", "base64", "chmod",
                   "sh", "bash", "zsh", "dash", "openssl", "crontab", "ssh", "scp"}
CREDENTIAL_HINTS = ("/.ssh/", "/.aws/", "/.netrc", "/.git-credentials",
                    "/.pypirc", "/.npmrc", "/etc/shadow", "/.docker/config")
PERSISTENCE_HINTS = ("/.bashrc", "/.bash_profile", "/.zshrc", "/.profile",
                     "/etc/cron", "/.ssh/authorized_keys", "/etc/systemd")


def external(ip: str) -> bool:
    return bool(ip) and not (ip.startswith("127.") or ip.startswith("10.")
                             or ip.startswith("192.168.") or ip == "0.0.0.0")


def analyse(path: Path) -> dict:
    ind = dict(exec_child=0, susp_exec=0, ext_connect=0, nonstd_port=0,
               cred_read=0, persist_write=0, write_outside=0, n_events=0)
    try:
        with open(path) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                ind["n_events"] += 1
                t = e.get("type")
                fn = e.get("fname", "") or ""
                comm = (e.get("comm") or "").rsplit("/", 1)[-1]

                if t == "exec":
                    ind["exec_child"] += 1
                    target = (fn or comm).rsplit("/", 1)[-1]
                    if target in SUSPICIOUS_BINS:
                        ind["susp_exec"] += 1
                elif t == "connect":
                    if external(e.get("daddr") or ""):
                        ind["ext_connect"] += 1
                    p = e.get("dport") or 0
                    if p and p not in (80, 443, 53):
                        ind["nonstd_port"] += 1
                if any(h in fn for h in CREDENTIAL_HINTS):
                    ind["cred_read"] += 1
                if e.get("write"):
                    if any(h in fn for h in PERSISTENCE_HINTS):
                        ind["persist_write"] += 1
                    if fn.startswith("/") and "site-packages" not in fn \
                            and not fn.startswith(("/tmp", "/proc", "/dev")):
                        ind["write_outside"] += 1
    except Exception:
        pass
    return ind


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", type=Path, default=Path("data/traces"))
    args = ap.parse_args()

    print("=" * 78)
    print("SIGNAL INVENTORY & DETECTION CEILING")
    print("=" * 78)

    # Indicators that constitute "observable malicious-looking behavior".
    KEYS = ["susp_exec", "ext_connect", "nonstd_port", "cred_read",
            "persist_write", "write_outside"]

    summary = {}
    for label, sub in ((0, "benign"), (1, "malware")):
        from scbf.dataset import ok_traces
        files = [Path(i["path"]) for i in ok_traces(args.traces, require_manifest=False)
                 if i["label"] == label]
        rows = [analyse(p) for p in files]
        rows = [r for r in rows if r["n_events"] > 0]
        summary[sub] = rows
        n = len(rows)
        if not n:
            print(f"\n{sub}: no traces")
            continue

        print(f"\n{sub.upper()}  (n={n})")
        print(f"  {'indicator':<18}{'traces with it':>16}{'% of class':>12}")
        print("  " + "-" * 46)
        for k in ["exec_child"] + KEYS:
            c = sum(1 for r in rows if r[k] > 0)
            print(f"  {k:<18}{c:>16}{c / n:>11.1%}")

        inert = sum(1 for r in rows if not any(r[k] > 0 for k in KEYS))
        print(f"\n  traces with NO suspicious indicator: {inert}/{n} = {inert / n:.1%}")

    mal = summary.get("malware", [])
    ben = summary.get("benign", [])
    if mal:
        inert = sum(1 for r in mal if not any(r[k] > 0 for k in KEYS))
        ceiling = 1 - inert / len(mal)
        print("\n" + "=" * 78)
        print("DETECTION CEILING")
        print("=" * 78)
        print(f"  {inert} of {len(mal)} malicious traces show no observable")
        print(f"  suspicious behavior on Linux (inert / Windows-targeted payloads).")
        print(f"\n  MAXIMUM ACHIEVABLE RECALL ~= {ceiling:.1%}")
        print("  No model can exceed this: there is no behavior to detect in")
        print("  those samples. Report it alongside any recall figure.")
        if ben:
            fp_risk = sum(1 for r in ben if any(r[k] > 0 for k in KEYS))
            print(f"\n  Benign traces that ALSO show indicators: {fp_risk}/{len(ben)} "
                  f"= {fp_risk / len(ben):.1%}")
            print("  These are the hard false positives (legitimate packages that")
            print("  download, write outside site-packages, or spawn shells).")
    print()


if __name__ == "__main__":
    main()
