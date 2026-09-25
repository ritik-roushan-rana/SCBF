"""
Batch trace collection for the SCBF dataset.

The single most important property of this script is that BENIGN AND
MALICIOUS PACKAGES GO THROUGH AN IDENTICAL CODE PATH, IN ONE INTERLEAVED
RUN. The previous dataset (zenodo_13746167) was collected with the two
classes in separate runs, and picked up a giveaway: 97.2% of benign traces
contained /dev/pts (a TTY was attached) and 0% of malicious ones did. A
one-line rule on that artifact scored 96.5% F1, and the trained model
inherited it -- 92.31% F1 that collapsed to 52.53% once the artifact was
removed.

Design rules enforced here:

  1. One process, one harness, one invocation style for every package.
  2. Labels are shuffled into a single work queue, so any environmental
     drift over the collection window hits both classes equally.
  3. Every trace is written with an environment fingerprint sidecar, so
     `scbf.audit.leakage` can prove after the fact that the classes were
     captured the same way.
  4. stdin/stdout/stderr are wired identically for every package
     (never a TTY), so /dev/pts can never separate the classes again.

Usage:
    sudo python3 capture/collect_dataset.py \
        --benign  data/raw/benign \
        --malware data/raw/malware \
        --out     data/traces \
        --python  /usr/bin/python3
"""

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MONITOR = HERE / "monitor.sh"

# Archive extensions pip can install from directly.
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".zip", ".whl", ".tar.bz2")


def find_packages(root: Path) -> list[Path]:
    """Every installable artifact under `root`, sorted for reproducibility."""
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name.endswith(ARCHIVE_SUFFIXES):
            out.append(p)
    return out


def env_fingerprint() -> dict:
    """Facts about the capture environment, recorded with every trace.

    If these ever differ systematically between classes, the dataset has a
    collection artifact and the audit will say so.
    """
    def _run(cmd):
        try:
            return subprocess.run(cmd, shell=True, capture_output=True,
                                  text=True, timeout=10).stdout.strip()
        except Exception:
            return ""

    return {
        "hostname": _run("hostname"),
        "kernel": _run("uname -r"),
        "python": _run("python3 -V"),
        "pip": _run("python3 -m pip -V"),
        "stdin_isatty": sys.stdin.isatty(),
        "stdout_isatty": sys.stdout.isatty(),
        "cwd": os.getcwd(),
        "user": _run("id -un"),
    }


TEMPLATE_TAR = Path(tempfile.gettempdir()) / "scbf_venv_template.tar"


def build_template(venv_dir: Path, python_bin: str) -> None:
    """Build the template venv once: pip + setuptools + wheel."""
    shutil.rmtree(venv_dir, ignore_errors=True)
    subprocess.run([python_bin, "-m", "venv", str(venv_dir)],
                   capture_output=True, timeout=300, check=True)
    # Seed the libraries package setup.py files commonly import at module
    # scope. `requests` matters most: a large share of PyPI malware does
    # `import requests` in setup.py to exfiltrate during install, and in a
    # bare venv that raises ModuleNotFoundError, so the payload never runs
    # and the trace contains no malicious behavior at all -- the install
    # merely fails. Dynamic analysis only works if the code actually runs.
    subprocess.run([str(venv_dir / "bin" / "python"), "-m", "pip", "install",
                    "-q", "--disable-pip-version-check",
                    "setuptools", "wheel", "requests", "urllib3", "certifi"],
                   capture_output=True, timeout=900, check=True)
    if TEMPLATE_TAR.exists():
        TEMPLATE_TAR.unlink()
    subprocess.run(["tar", "cf", str(TEMPLATE_TAR), "-C", str(venv_dir.parent),
                    venv_dir.name], capture_output=True, timeout=300, check=True)
    print(f"[+] venv template built: {TEMPLATE_TAR} "
          f"({TEMPLATE_TAR.stat().st_size // 1024} KB)")


def restore_template(venv_dir: Path, python_bin: str) -> None:
    """Restore the template. Offline and identical for every package."""
    if not TEMPLATE_TAR.exists():
        build_template(venv_dir, python_bin)
        return
    shutil.rmtree(venv_dir, ignore_errors=True)
    subprocess.run(["tar", "xf", str(TEMPLATE_TAR), "-C", str(venv_dir.parent)],
                   capture_output=True, timeout=300, check=True)
    # The collector runs as root, but monitor.sh drops to SUDO_USER to run
    # pip (so the venv does not fill with root-owned files). Hand the venv
    # to that user, or every install dies on a write permission error.
    drop_user = os.environ.get("SCBF_USER") or os.environ.get("SUDO_USER")
    if drop_user:
        subprocess.run(["chown", "-R", f"{drop_user}:{drop_user}", str(venv_dir)],
                       capture_output=True, timeout=120)


def capture_one(pkg: Path, label: int, out_dir: Path, python_bin: str,
                timeout: int) -> dict:
    """Run one package through the monitor. Identical for both labels."""
    name = pkg.name
    for suf in ARCHIVE_SUFFIXES:
        if name.endswith(suf):
            name = name[: -len(suf)]
            break

    trace_path = out_dir / ("malware" if label else "benign") / "traces" / f"{name}.jsonl"
    trace_path.parent.mkdir(parents=True, exist_ok=True)

    # Each package gets a pristine venv at a FIXED path, restored from a
    # pre-built template so every package starts from a byte-identical
    # environment. The template already contains setuptools/wheel, because
    # Python 3.12+ venvs ship only pip and --no-build-isolation then fails
    # every sdist with "Cannot import setuptools.build_meta". Seeding here,
    # BEFORE the monitor starts, keeps it out of the trace.
    venv_dir = Path(tempfile.gettempdir()) / "scbf_capture_env"
    restore_template(venv_dir, python_bin)

    started = time.time()
    status = "ok"
    try:
        venv_python = venv_dir / "bin" / "python"

        # stdin from /dev/null and piped stdout/stderr for EVERY package:
        # no TTY is ever attached, to either class.
        proc = subprocess.run(
            ["bash", str(MONITOR), name, str(venv_python), str(pkg), str(trace_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        if proc.returncode != 0:
            status = f"monitor_rc={proc.returncode}"
    except subprocess.TimeoutExpired:
        status = "timeout"
    except Exception as exc:
        status = f"error:{type(exc).__name__}"
    finally:
        shutil.rmtree(venv_dir, ignore_errors=True)

    n_events = 0
    if trace_path.exists():
        with open(trace_path) as f:
            n_events = sum(1 for _ in f)
    if n_events == 0:
        status = "empty_trace" if status == "ok" else status

    return {
        "package": name,
        "artifact": str(pkg),
        "label": label,
        "trace": str(trace_path),
        "status": status,
        "n_events": n_events,
        "duration_s": round(time.time() - started, 2),
        "captured_at": time.time(),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign", required=True, type=Path)
    ap.add_argument("--malware", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--limit", type=int, default=0,
                    help="Capture at most N packages per class (smoke tests).")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--restart", action="store_true",
                    help="Ignore an existing manifest and capture everything again.")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("[ERROR] eBPF capture must run as root (use sudo).")
        sys.exit(1)

    benign = find_packages(args.benign)
    malware = find_packages(args.malware)
    if args.limit:
        benign, malware = benign[: args.limit], malware[: args.limit]

    print(f"[+] benign artifacts : {len(benign)}")
    print(f"[+] malware artifacts: {len(malware)}")
    if not benign or not malware:
        print("[ERROR] Need both classes present.")
        sys.exit(1)

    # THE ANTI-ARTIFACT STEP: one shuffled queue, both classes interleaved.
    # The shuffle is seeded, so the queue order is deterministic and a
    # resumed run keeps the same interleaving.
    queue = [(p, 0) for p in benign] + [(p, 1) for p in malware]
    random.Random(args.seed).shuffle(queue)

    # RESUME: skip packages already captured successfully. Lets a run be
    # stopped (network change, reboot) and restarted without losing work
    # or disturbing the interleaved order.
    already = set()
    manifest_existing = args.out / "manifest.jsonl"
    if manifest_existing.exists() and not args.restart:
        with open(manifest_existing) as f:
            for line in f:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if r.get("status") == "ok":
                    already.add(r.get("artifact"))
        if already:
            before = len(queue)
            queue = [(pk, lb) for pk, lb in queue if str(pk) not in already]
            print(f"[+] RESUMING: {len(already)} already captured, "
                  f"{len(queue)} of {before} remaining")

    args.out.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out / "manifest.jsonl"
    fingerprint = env_fingerprint()
    with open(args.out / "environment.json", "w") as f:
        json.dump(fingerprint, f, indent=2)
    print(f"[+] environment: kernel={fingerprint['kernel']} "
          f"stdout_isatty={fingerprint['stdout_isatty']}")
    print("[+] building venv template (setuptools/wheel pre-seeded)...")
    build_template(Path(tempfile.gettempdir()) / "scbf_capture_env", args.python)
    print(f"[+] capturing {len(queue)} packages (interleaved, seed={args.seed})\n")

    done = {"ok": 0, "failed": 0}
    with open(manifest_path, "a") as mf:
        for i, (pkg, label) in enumerate(queue, 1):
            rec = capture_one(pkg, label, args.out, args.python, args.timeout)
            mf.write(json.dumps(rec) + "\n")
            mf.flush()
            ok = rec["status"] == "ok"
            done["ok" if ok else "failed"] += 1
            tag = "malware" if label else "benign "
            print(f"[{i}/{len(queue)}] {tag} {rec['package'][:44]:<44} "
                  f"{rec['status']:<14} {rec['n_events']:>7} events "
                  f"{rec['duration_s']:>6.1f}s")

    print(f"\n[+] done: {done['ok']} captured, {done['failed']} failed")
    print(f"[+] manifest: {manifest_path}")
    print(f"[+] next: python3 -m scbf.audit.leakage --traces {args.out}")


if __name__ == "__main__":
    main()
