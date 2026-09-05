#!/bin/bash
# Check training progress

echo "==========================================="
echo "SCBF Training Progress Monitor"
echo "==========================================="
echo ""

# Check if process is running
if pgrep -f "train_with_split" > /dev/null; then
    echo "✓ Training is RUNNING"
else
    echo "⚠ Training is NOT running (may have finished or stopped)"
fi

echo ""
echo "Latest checkpoints:"
ls -lht models/checkpoints/*.pt 2>/dev/null | head -5

echo ""
echo "==========================================="
echo "Recent training output (last 30 lines):"
echo "==========================================="

# Find the training log or show checkpoints
if [ -f "training.log" ]; then
    tail -30 training.log
else
    # Show latest epochs by checkpoint modification time
    echo "Check the terminal where training is running for live output"
    echo ""
    echo "Checkpoints saved:"
    ls -1 models/checkpoints/*.pt 2>/dev/null | tail -5
fi

echo ""
echo "==========================================="
echo "To evaluate current best model:"
echo "  .venv/bin/python quick_eval.py"
echo ""
echo "To see live output, use the terminal where"
echo "you started training, or check Kiro output"
echo "==========================================="
