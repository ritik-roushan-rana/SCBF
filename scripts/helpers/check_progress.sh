#!/bin/bash
# Quick progress check

cd /Users/shield/Downloads/scbf

echo "=========================================="
echo "SCBF Training Progress"
echo "=========================================="
echo ""

# Check if running
if ps -p $(cat training.pid 2>/dev/null) >/dev/null 2>&1; then
    echo "✓ Training is RUNNING"
    echo "  PID: $(cat training.pid)"
else
    echo "⚠ Training is NOT running"
    echo ""
    if [ -f "models/tgn_v2_best.pt" ]; then
        echo "✓ Training COMPLETED! Best model saved."
        echo ""
        echo "Run evaluation:"
        echo "  .venv/bin/python quick_eval.py"
        exit 0
    else
        echo "❌ Training may have crashed"
        echo "Check log: cat training_v3.log | tail -50"
        exit 1
    fi
fi

echo ""

# Count epochs completed
EPOCH_COUNT=$(ls models/checkpoints/tgn_epoch*.pt 2>/dev/null | wc -l | tr -d ' ')
echo "Epochs completed: $EPOCH_COUNT / 60"

# Show latest checkpoint
if [ $EPOCH_COUNT -gt 0 ]; then
    LATEST=$(ls -t models/checkpoints/tgn_epoch*.pt | head -1)
    echo "Latest checkpoint: $(basename $LATEST)"
    echo "Created: $(stat -f "%Sm" $LATEST)"
fi

echo ""

# Show last few log lines (if log has content)
if [ -s training_v3.log ]; then
    echo "Latest training output:"
    echo "------------------------------------------"
    tail -15 training_v3.log
else
    echo "Log file empty (output may be buffered)"
    echo "Check checkpoints instead"
fi

echo ""
echo "=========================================="
echo "Run this again: ./check_progress.sh"
echo "=========================================="
