#!/bin/bash
# Prepare dataset for Google Colab training

echo "=========================================="
echo "Preparing SCBF Data for Google Colab"
echo "=========================================="
echo ""

cd /Users/shield/Downloads/scbf

# Check dataset exists
echo "Checking dataset..."
BENIGN_COUNT=$(ls data/zenodo_13746167/benign/traces/*.jsonl 2>/dev/null | wc -l | tr -d ' ')
MALWARE_COUNT=$(ls data/zenodo_13746167/malware/traces/*.jsonl 2>/dev/null | wc -l | tr -d ' ')

if [ "$BENIGN_COUNT" -eq 0 ] || [ "$MALWARE_COUNT" -eq 0 ]; then
    echo "❌ Error: Dataset not found or empty"
    echo ""
    echo "Expected:"
    echo "  data/zenodo_13746167/benign/traces/*.jsonl"
    echo "  data/zenodo_13746167/malware/traces/*.jsonl"
    exit 1
fi

echo "✓ Found $BENIGN_COUNT benign packages"
echo "✓ Found $MALWARE_COUNT malware packages"
echo ""

# Calculate size
DATASET_SIZE=$(du -sh data/zenodo_13746167 | cut -f1)
echo "Dataset size: $DATASET_SIZE"
echo ""

# Create zip
echo "Creating zip file..."
echo "This may take a few minutes..."
zip -r scbf_data.zip data/zenodo_13746167/ -q

if [ $? -eq 0 ]; then
    ZIP_SIZE=$(du -sh scbf_data.zip | cut -f1)
    echo "✓ Created: scbf_data.zip ($ZIP_SIZE)"
    echo ""
    echo "=========================================="
    echo "Next Steps:"
    echo "=========================================="
    echo ""
    echo "1. Upload to Google Colab:"
    echo "   - Go to https://colab.research.google.com"
    echo "   - Upload SCBF_Training_Colab.ipynb"
    echo "   - Enable GPU: Runtime > Change runtime type > GPU"
    echo ""
    echo "2. Upload dataset:"
    echo "   Option A: Direct upload (slower)"
    echo "     - Use Colab file browser to upload scbf_data.zip"
    echo ""
    echo "   Option B: Google Drive (recommended)"
    echo "     - Upload scbf_data.zip to Google Drive"
    echo "     - Mount Drive in Colab notebook"
    echo ""
    echo "3. Run notebook:"
    echo "   - Click Runtime > Run all"
    echo "   - Training takes ~30-60 minutes with GPU"
    echo ""
    echo "4. Download trained model:"
    echo "   - models/tgn_v2_best.pt"
    echo "   - Place in: $(pwd)/models/"
    echo ""
    echo "=========================================="
    echo ""
    echo "Files ready:"
    echo "  ✓ scbf_data.zip ($ZIP_SIZE)"
    echo "  ✓ SCBF_Training_Colab.ipynb"
    echo "  ✓ COLAB_INSTRUCTIONS.md (read this!)"
    echo ""
else
    echo "❌ Failed to create zip file"
    exit 1
fi
