"""
Single source of truth for which traces are part of the dataset.

Only traces whose install SUCCEEDED are usable. This is not a detail.

The collector writes a trace file for every attempt, including installs
that failed -- 150 of the first 152 failures left a usable-looking .jsonl.
Failed installs are not merely noisy, they are a leak: a failed build has
a distinctive shape (no site-packages writes, truncated, error paths), and
the failure rate is class-correlated (32.1% of benign attempts vs 20.1% of
malicious ones in this collection, because real libraries have far more
ways to fail to build than a 20-line malicious setup.py).

Train on all files and the model learns "looks like a failed install =>
benign". That is the same failure mode as the /dev/pts artifact that gave
v1 its 92.31% F1: a property of COLLECTION that correlates with the label
and is readable straight off the trace.

So every consumer -- training, baselines, the audit, the signal report --
goes through here, and here reads the manifest.
"""

import json
from pathlib import Path


def load_manifest(traces_root: Path) -> list[dict]:
    mf = Path(traces_root) / "manifest.jsonl"
    if not mf.exists():
        return []
    out = []
    with open(mf) as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def ok_traces(traces_root: Path, require_manifest: bool = True) -> list[dict]:
    """Traces from installs that actually succeeded, as {path, label} dicts.

    With no manifest, falls back to globbing and prints a loud warning --
    those results must not be reported.
    """
    traces_root = Path(traces_root)
    manifest = load_manifest(traces_root)

    if not manifest:
        if require_manifest:
            raise SystemExit(
                f"No manifest.jsonl under {traces_root}. Refusing to build a "
                "dataset by globbing, because that silently includes failed "
                "installs (see scbf/dataset.py). Re-run the capture, or pass "
                "require_manifest=False and do not report the numbers."
            )
        items = []
        for label, sub in ((0, "benign"), (1, "malware")):
            for p in sorted((traces_root / sub / "traces").glob("*.jsonl")):
                items.append({"path": str(p), "label": label})
        print("WARNING: no manifest — dataset includes FAILED installs. "
              "Metrics from this are not trustworthy.")
        return items

    items = []
    for r in manifest:
        if r.get("status") != "ok":
            continue
        p = Path(r["trace"])
        if not p.is_absolute():
            p = traces_root.parent.parent / p if not p.exists() else p
        if p.exists() and p.stat().st_size > 0:
            items.append({"path": str(p), "label": int(r["label"]),
                          "package": r.get("package", p.stem)})
    return items


def dataset_summary(traces_root: Path) -> str:
    manifest = load_manifest(traces_root)
    items = ok_traces(traces_root, require_manifest=False)
    n_b = sum(1 for i in items if i["label"] == 0)
    n_m = sum(1 for i in items if i["label"] == 1)
    att_b = sum(1 for r in manifest if r.get("label") == 0)
    att_m = sum(1 for r in manifest if r.get("label") == 1)
    return (f"usable {len(items)} traces  (benign {n_b}/{att_b}, "
            f"malicious {n_m}/{att_m}); "
            f"{len(manifest) - len(items)} failed installs EXCLUDED")
