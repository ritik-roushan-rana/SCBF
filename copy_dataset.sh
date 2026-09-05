#!/bin/bash
#
# Copy dataset from dataset_setup_monitor to main SCBF directory
#
# Usage: ./copy_dataset.sh
#

SOURCE_DIR="dataset_setup_monitor/data/zenodo_13746167"
TARGET_DIR="data/zenodo_13746167"

echo "====================================================================="
echo "SCBF Dataset Copy Script"
echo "====================================================================="
echo ""
echo "This will copy your dataset from:"
echo "  SOURCE: $SOURCE_DIR"
echo "  TARGET: $TARGET_DIR"
echo ""

# Check if source exists
if [ ! -d "$SOURCE_DIR" ]; then
    echo "❌ ERROR: Source directory not found: $SOURCE_DIR"
    echo ""
    echo "Expected structure:"
    echo "  dataset_setup_monitor/data/zenodo_13746167/"
    exit 1
fi

# Count files
MALWARE_COUNT=$(find "$SOURCE_DIR/malware/traces" -name "*.jsonl" 2>/dev/null | wc -l | tr -d ' ')
BENIGN_COUNT=$(find "$SOURCE_DIR/benign/traces" -name "*.jsonl" 2>/dev/null | wc -l | tr -d ' ')

echo "Found in source:"
echo "  Malware traces: $MALWARE_COUNT files"
echo "  Benign traces:  $BENIGN_COUNT files"
echo "  Total:          $((MALWARE_COUNT + BENIGN_COUNT)) trace files"
echo ""

# Check if target exists and has data
if [ -d "$TARGET_DIR/malware/traces" ] && [ "$(ls -A $TARGET_DIR/malware/traces 2>/dev/null)" ]; then
    echo "⚠️  WARNING: Target directory already contains data!"
    echo ""
    read -p "Overwrite existing data? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Aborted."
        exit 0
    fi
    echo ""
fi

# Create target structure
echo "Creating target directory structure..."
mkdir -p "$TARGET_DIR/malware/traces"
mkdir -p "$TARGET_DIR/malware/data"
mkdir -p "$TARGET_DIR/benign/traces"
mkdir -p "$TARGET_DIR/benign/data"
echo "✓ Structure created"
echo ""

# Copy trace files
echo "Copying trace files..."
echo "  Copying malware traces..."
cp "$SOURCE_DIR/malware/traces"/*.jsonl "$TARGET_DIR/malware/traces/" 2>/dev/null
echo "  ✓ $MALWARE_COUNT malware traces copied"

echo "  Copying benign traces..."
cp "$SOURCE_DIR/benign/traces"/*.jsonl "$TARGET_DIR/benign/traces/" 2>/dev/null
echo "  ✓ $BENIGN_COUNT benign traces copied"
echo ""

# Copy aggregated files (if they exist)
echo "Copying aggregated files (optional)..."
if [ -f "$SOURCE_DIR/malware/data/malware.jsonl" ]; then
    cp "$SOURCE_DIR/malware/data/malware.jsonl" "$TARGET_DIR/malware/data/"
    SIZE=$(ls -lh "$TARGET_DIR/malware/data/malware.jsonl" | awk '{print $5}')
    echo "  ✓ malware.jsonl copied ($SIZE)"
fi

if [ -f "$SOURCE_DIR/benign/data/benign.jsonl" ]; then
    cp "$SOURCE_DIR/benign/data/benign.jsonl" "$TARGET_DIR/benign/data/"
    SIZE=$(ls -lh "$TARGET_DIR/benign/data/benign.jsonl" | awk '{print $5}')
    echo "  ✓ benign.jsonl copied ($SIZE)"
fi
echo ""

# Verify copy
COPIED_MALWARE=$(find "$TARGET_DIR/malware/traces" -name "*.jsonl" 2>/dev/null | wc -l | tr -d ' ')
COPIED_BENIGN=$(find "$TARGET_DIR/benign/traces" -name "*.jsonl" 2>/dev/null | wc -l | tr -d ' ')

echo "====================================================================="
echo "COPY COMPLETE"
echo "====================================================================="
echo ""
echo "Verification:"
echo "  Malware traces: $COPIED_MALWARE files"
echo "  Benign traces:  $COPIED_BENIGN files"
echo "  Total:          $((COPIED_MALWARE + COPIED_BENIGN)) trace files"
echo ""
echo "Dataset location:"
echo "  $TARGET_DIR/malware/traces/*.jsonl"
echo "  $TARGET_DIR/benign/traces/*.jsonl"
echo ""

if [ $COPIED_MALWARE -eq 0 ] || [ $COPIED_BENIGN -eq 0 ]; then
    echo "❌ ERROR: Copy failed! No files in target directory."
    exit 1
fi

echo "Next steps:"
echo "  1. Validate dataset:"
echo "     make validate-data"
echo ""
echo "  2. Train model:"
echo "     sudo make train-split"
echo ""
echo "====================================================================="
