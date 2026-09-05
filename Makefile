.PHONY: help install test clean collect-data prepare-structure aggregate-data validate-data train train-split evaluate scan

help:
	@echo "SCBF - Supply Chain Behavioral Fingerprinting"
	@echo ""
	@echo "Dataset Preparation:"
	@echo "  make prepare-structure  Create Zenodo dataset directory structure"
	@echo "  make collect-data       Collect clean + malicious training data"
	@echo "  make aggregate-data     Merge per-package files into Zenodo structure"
	@echo "  make validate-data      Validate dataset integrity"
	@echo ""
	@echo "Training & Evaluation:"
	@echo "  make train              Train TGN model (original - no split)"
	@echo "  make train-split        Train TGN model with train/val/test split"
	@echo "  make evaluate           Evaluate trained model on test set"
	@echo ""
	@echo "Other Commands:"
	@echo "  make install            Install package in development mode"
	@echo "  make scan               Run example scan (requires package name)"
	@echo "  make test               Run test suite"
	@echo "  make clean              Remove generated files"
	@echo ""
	@echo "Complete Workflow:"
	@echo "  1. sudo make prepare-structure"
	@echo "  2. sudo make collect-data"
	@echo "  3. make aggregate-data"
	@echo "  4. make validate-data"
	@echo "  5. sudo make train-split"
	@echo "  6. make evaluate"
	@echo "  7. sudo make scan PKG=requests"

install:
	pip install -e .

prepare-structure:
	@echo "Creating Zenodo dataset directory structure..."
	mkdir -p data/zenodo_13746167/{malware,benign}/{data,traces}
	@echo "✓ Directory structure created"
	@echo ""
	@echo "Structure:"
	@echo "  data/zenodo_13746167/malware/{data,traces}"
	@echo "  data/zenodo_13746167/benign/{data,traces}"
	@echo ""
	@echo "Place your dataset files here:"
	@echo "  - data/zenodo_13746167/malware/traces/*.jsonl"
	@echo "  - data/zenodo_13746167/benign/traces/*.jsonl"
	@echo ""
	@echo "Or use collection script:"
	@echo "  python3 scripts/collect_zenodo.py"

collect-data:
	@echo "Collecting behavioral data from packages..."
	@echo ""
	@echo "Use the collection script:"
	@echo "  python3 scripts/collect_zenodo.py [OPTIONS]"
	@echo ""
	@echo "Options:"
	@echo "  --max-artifacts N    Limit to N packages (default: 1500)"
	@echo "  --skip-malware       Skip malware collection"
	@echo "  --skip-benign        Skip benign collection"
	@echo ""
	@echo "Example:"
	@echo "  python3 scripts/collect_zenodo.py --max-artifacts 1000"
	@echo ""
	@echo "Or if you already have dataset files:"
	@echo "  ./copy_dataset.sh"

aggregate-data:
	@echo "Aggregating per-package files into Zenodo structure..."
	python scripts/aggregate_jsonl.py
	@echo ""
	@echo "Next: make validate-data"

validate-data:
	@echo "Validating dataset integrity..."
	python scripts/validate_dataset.py

train:
	@echo "Training TGN model (original - no split)..."
	sudo python -m scbf.training.train
	@echo ""
	@echo "Building behavioral envelope..."
	sudo python -m scbf.training.build_envelope
	@echo ""
	@echo "Checking separation..."
	sudo python scripts/check_distances.py

train-split:
	@echo "Training TGN model with train/val/test split..."
	@if [ -f .venv/bin/python ]; then \
		echo "Using virtual environment: .venv/bin/python"; \
		.venv/bin/python -m scbf.training.train_with_split; \
	else \
		echo "Using system Python"; \
		python3 -m scbf.training.train_with_split; \
	fi
	@echo ""
	@echo "Building behavioral envelope..."
	sudo python -m scbf.training.build_envelope
	@echo ""
	@echo "Training complete! Run 'make evaluate' to see test results."

evaluate:
	@echo "Evaluating model on test set..."
	sudo python -m scbf.training.evaluate

scan:
	@if [ -z "$(PKG)" ]; then \
		echo "Error: Package name required. Usage: make scan PKG=requests"; \
		exit 1; \
	fi
	@echo "Scanning package: $(PKG)"
	sudo python -m scbf.detection.cli --package $(PKG)

test:
	pytest tests/ -v

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -f last_capture.jsonl
	rm -rf build/ dist/
