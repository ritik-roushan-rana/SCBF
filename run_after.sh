#!/bin/bash
# Waits for v2 and v3, picks the winner ON VALIDATION, evaluates it on test,
# then cross-validates that config for the OSCAR-comparable number.
cd "$(dirname "$0")"
PY=/Users/shield/Downloads/scbf/.venv/bin/python
exec >> select_and_cv.log 2>&1

while pgrep -f "scbf.training.trai[n]" >/dev/null; do sleep 120; done
echo "=== both variants finished $(date +%H:%M) ==="

v2=$(grep -o "val F1=[0-9.]*" train_mac_v2.log | tail -1 | tr -d 'valF1=')
v3=$(grep -o "val F1=[0-9.]*" train_mac_v3.log | tail -1 | tr -d 'valF1=')
echo "best val F1 -> v2=$v2  v3=$v3"

# select on VALIDATION only (never on test)
if [ -n "$v3" ] && awk "BEGIN{exit !($v3 > $v2)}"; then
  WIN=v3; PW=2.0; MODELS=models_v3
else
  WIN=v2; PW=1.0; MODELS=models
fi
echo "WINNER (by val): $WIN  (pw-mult=$PW)"

echo "=== TEST EVALUATION OF WINNER ==="
$PY -m scbf.training.evaluate --traces data/traces --models $MODELS

echo "=== 5-FOLD CROSS-VALIDATION (OSCAR-comparable, all 389 malicious) ==="
$PY -m scbf.training.cross_validate --traces data/traces --folds 5 \
    --lr 5e-4 --pw-mult $PW --out models/cv_results_${WIN}.json
echo "=== ALL DONE $(date +%H:%M) ==="
