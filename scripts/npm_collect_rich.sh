#!/bin/bash
#
# Batch-capture rich NPM traces for every tarball in a directory.
#
#   sudo -E ./scripts/npm_collect_rich.sh TGZ_DIR OUT_DIR [extra npm_capture_rich.py args]
#
# Example (run once for benign, once for malware):
#   sudo -E ./scripts/npm_collect_rich.sh ~/rq1_npm_benign            ~/rq1_npm_rich/benign/traces
#   sudo -E ./scripts/npm_collect_rich.sh ~/rq1_npm_malware/npm_malware ~/rq1_npm_rich/malware/traces
#
# Already-captured tarballs (OUT_DIR/<name>.jsonl exists) are skipped, so the
# script can be re-run after an interruption. A per-run summary is appended to
# OUT_DIR/../collection_summary.jsonl.
#
# Run this inside a throwaway VM with snapshots: the malware payloads DO
# execute (that is the point), and the require() phase imports the package.

set -u

TGZ_DIR="${1:-}"
OUT_DIR="${2:-}"
shift 2 || true
EXTRA_ARGS=("$@")

if [ -z "$TGZ_DIR" ] || [ -z "$OUT_DIR" ]; then
    echo "Usage: sudo -E $0 TGZ_DIR OUT_DIR [--no-require] [--install-timeout N]"
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] must run as root (eBPF). Use: sudo -E $0 ..."
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
CAPTURE="$HERE/npm_capture_rich.py"
mkdir -p "$OUT_DIR"
SUMMARY="$(dirname "$OUT_DIR")/collection_summary.jsonl"

shopt -s nullglob
TARBALLS=("$TGZ_DIR"/*.tgz "$TGZ_DIR"/*.tar.gz)
TOTAL=${#TARBALLS[@]}
echo "[+] $TOTAL tarballs in $TGZ_DIR -> $OUT_DIR"

i=0; ok=0; failed=0; skipped=0
for tgz in "${TARBALLS[@]}"; do
    i=$((i + 1))
    name="$(basename "$tgz")"; name="${name%.tgz}"; name="${name%.tar.gz}"
    out="$OUT_DIR/$name.jsonl"
    if [ -s "$out" ]; then
        skipped=$((skipped + 1)); continue
    fi
    echo "------------------------------------------------------------"
    echo "[$i/$TOTAL] $name"

    # a stray npm/node from a previous package must not pollute this trace
    pkill -KILL -f "scbf-npm-install-" 2>/dev/null || true

    if python3 "$CAPTURE" "$tgz" "$out" "${EXTRA_ARGS[@]}" 2>&1 | tee /tmp/scbf-capture.log | grep -E "^\[\+\] \{" >> "$SUMMARY"; then
        ok=$((ok + 1))
    else
        # capture ran but npm install returned non-zero; the trace is still valid
        # (a failing install is behavior too) as long as it has events
        if [ -s "$out" ]; then ok=$((ok + 1)); else failed=$((failed + 1)); rm -f "$out"; fi
    fi
    tail -n 1 /tmp/scbf-capture.log

    # keep /tmp clean even if the capture crashed before its own cleanup
    rm -rf /tmp/scbf-npm-pkg-* /tmp/scbf-npm-install-* /tmp/scbf-npm-cache-* 2>/dev/null || true
done

echo "============================================================"
echo "[+] done: captured=$ok failed=$failed skipped(existing)=$skipped"
echo "[+] traces : $OUT_DIR"
echo "[+] summary: $SUMMARY"
