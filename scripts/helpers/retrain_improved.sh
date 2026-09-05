#!/bin/bash
# Retrain with improved loss function

echo "========================================="
echo "SCBF Model Retraining (Improved)"
echo "========================================="
echo ""

# Backup old model
if [ -f "models/tgn_v2_best.pt" ]; then
    echo "Backing up old model..."
    mv models/tgn_v2_best.pt models/tgn_v2_old_margin0.8.pt
    echo "  ✓ Saved to: models/tgn_v2_old_margin0.8.pt"
fi

if [ -d "models/checkpoints" ]; then
    echo "Backing up old checkpoints..."
    mv models/checkpoints models/checkpoints_old
    mkdir -p models/checkpoints
    echo "  ✓ Saved to: models/checkpoints_old/"
fi

echo ""
echo "========================================="
echo "Starting Training with Improved Settings"
echo "========================================="
echo ""
echo "Improvements:"
echo "  • Margin: 0.8 → 2.0 (stronger separation)"
echo "  • Separation weight: 1.0x → 2.0x"
echo "  • Fixed distance calculation (L2 instead of squared)"
echo ""
echo "Expected improvements:"
echo "  • Malicious distance: 0.57 → 1.5-2.0"
echo "  • Recall: 8.62% → >70%"
echo "  • Accuracy: 71.78% → >85%"
echo ""
echo "Starting training... (this will take 1-2 hours)"
echo ""

# Train
if [ -f ".venv/bin/python" ]; then
    .venv/bin/python -m scbf.training.train_with_split
else
    python3 -m scbf.training.train_with_split
fi

TRAIN_EXIT=$?

if [ $TRAIN_EXIT -eq 0 ]; then
    echo ""
    echo "========================================="
    echo "Training Complete! Running Quick Eval..."
    echo "========================================="
    echo ""
    
    # Quick evaluation
    if [ -f ".venv/bin/python" ]; then
        .venv/bin/python quick_eval.py
    else
        python3 quick_eval.py
    fi
    
    echo ""
    echo "========================================="
    echo "Done! Compare results:"
    echo "========================================="
    echo ""
    echo "Old model (margin=0.8):"
    echo "  Accuracy: 71.78%, Recall: 8.62%, F1: 14.93%"
    echo ""
    echo "New model results shown above ↑"
    echo ""
    echo "To restore old model:"
    echo "  mv models/tgn_v2_old_margin0.8.pt models/tgn_v2_best.pt"
    echo ""
else
    echo ""
    echo "Training failed! Check errors above."
    exit 1
fi
