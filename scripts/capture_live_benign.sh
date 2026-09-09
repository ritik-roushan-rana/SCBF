#!/bin/bash
#
# Capture live syscall traces of well-known clean PyPI packages on THIS host,
# so the behavioral envelope can be calibrated against the actual pip /
# Python / cache layout used at scan time.
#
# Without this, live `make scan PKG=...` calls drift out of distribution
# because the Zenodo training traces were captured in a different environment.
#
# Usage:
#   sudo -E ./scripts/capture_live_benign.sh
#
# After it finishes, rebuild the envelope:
#   make build-envelope
#
# Then live scans (`sudo -E make scan PKG=flask`) should return ALLOW for
# clean packages.

set -u

if [ "$EUID" -ne 0 ]; then
    echo "Must run as root (eBPF requires it):"
    echo "  sudo -E ./scripts/capture_live_benign.sh"
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

MONITOR="$REPO_ROOT/monitor.sh"
OUT_DIR="$REPO_ROOT/data/traces/live_benign"
PYTHON_BIN="${PYTHON_BIN:-$REPO_ROOT/.venv/bin/python}"

if [ ! -x "$MONITOR" ]; then
    echo "monitor.sh not found or not executable at $MONITOR"
    exit 1
fi

if [ ! -x "$PYTHON_BIN" ]; then
    echo "Python binary not found at $PYTHON_BIN"
    echo "Set PYTHON_BIN=<path> to override."
    exit 1
fi

mkdir -p "$OUT_DIR"

# Curated list of small-to-medium PURE-PYTHON packages that are unambiguously
# clean. Kept diverse (CLI, web, parsing, data, testing) so the envelope sees
# a realistic mix of clean install patterns on this VM.
PACKAGES=(
    six
    idna
    tomli
    colorama
    attrs
    click
    packaging
    typing-extensions
    wheel
    jsonlines
    charset-normalizer
    certifi
    urllib3
    requests
    flask
    werkzeug
    jinja2
    markupsafe
    itsdangerous
    blinker
    pyyaml
    python-dateutil
    pytz
    rich
    httpx
    pydantic
    fastapi
    starlette
    uvicorn
    pytest
)

echo "============================================================"
echo "[+] Capturing ${#PACKAGES[@]} clean packages to $OUT_DIR"
echo "[+] Python: $PYTHON_BIN"
echo "============================================================"

captured=0
failed=0

for pkg in "${PACKAGES[@]}"; do
    out="$OUT_DIR/${pkg}.jsonl"

    if [ -s "$out" ]; then
        echo "[skip] $pkg (already captured)"
        continue
    fi

    echo
    echo "[+] Capturing: $pkg"
    echo "----------------------------------------"

    if "$MONITOR" "$pkg" "$PYTHON_BIN" "$pkg" "$out"; then
        if [ -s "$out" ]; then
            captured=$((captured + 1))
            echo "[✓] $pkg — $(wc -l < "$out") events"
        else
            failed=$((failed + 1))
            rm -f "$out"
            echo "[✗] $pkg — empty trace, discarded"
        fi
    else
        failed=$((failed + 1))
        rm -f "$out"
        echo "[✗] $pkg — monitor failed"
    fi
done

echo
echo "============================================================"
echo "[+] Capture complete"
echo "[+] Captured : $captured"
echo "[+] Failed   : $failed"
echo "[+] Output   : $OUT_DIR"
echo "============================================================"
echo
echo "Next step — rebuild envelope with these traces:"
echo "  make build-envelope"
