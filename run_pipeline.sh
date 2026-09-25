#!/bin/bash
# Full post-capture pipeline. Runs unattended after collection finishes.
#
# Stops at the audit if the dataset shows a collection artifact -- training
# on a flagged dataset only manufactures another inflated number.
set -u
cd "$(dirname "$0")"
PY=.venv/bin/python
LOG=~/pipeline.log
exec > >(tee -a "$LOG") 2>&1

banner () { echo; echo "################################################################"; echo "# $1"; echo "################################################################"; date; echo; }

banner "STEP 1/6  LEAKAGE AUDIT (gate)"
$PY -m scbf.audit.leakage --traces data/traces --strict
AUDIT=$?
if [ $AUDIT -ne 0 ]; then
  banner "PIPELINE STOPPED — DATASET FAILED THE AUDIT"
  echo "A token or feature separates the classes. This is the /dev/pts failure"
  echo "mode. Fix the capture and re-collect; do NOT train on this dataset."
  exit 1
fi
echo "AUDIT PASSED — dataset is clean, continuing."

banner "STEP 2+3/6  SIGNAL INVENTORY & DETECTION CEILING"
$PY -m scbf.audit.signal_report --traces data/traces

banner "STEP 4/6  TABULAR BASELINES (the bar the TGN must clear)"
$PY -m scbf.training.baseline --traces data/traces

banner "STEP 5/6  TRAIN HYBRID TGN"
$PY -m scbf.training.train --traces data/traces

banner "STEP 6/6  FINAL EVALUATION"
$PY -m scbf.training.evaluate --traces data/traces

banner "PIPELINE COMPLETE"
echo "Artifacts:"
ls -la models/*.json models/*.pt 2>/dev/null
