.PHONY: help install test clean collect-data train train-split evaluate scan

help:
	@echo "SCBF - Supply Chain Behavioral Fingerprinting"
	@echo ""
	@echo "Usage:"
	@echo "  make install        Install package in development mode"
	@echo "  make collect-data   Collect clean + malicious training data"
	@echo "  make train          Train TGN model (original - no split)"
	@echo "  make train-split    Train TGN model with train/val/test split"
	@echo "  make evaluate       Evaluate trained model on test set"
	@echo "  make scan           Run example scan (requires package name)"
	@echo "  make test           Run test suite"
	@echo "  make clean          Remove generated files"
	@echo ""
	@echo "Examples:"
	@echo "  sudo make collect-data"
	@echo "  sudo make train-split     # Recommended"
	@echo "  sudo make evaluate"
	@echo "  sudo make scan PKG=requests"

install:
	pip install -e .

collect-data:
	@echo "Collecting clean package data..."
	sudo python scripts/collect_clean_data.py
	@echo ""
	@echo "Collecting malicious package data..."
	sudo python scripts/collect_malicious_data.py
	@echo ""
	@echo "Done. Check data/clean/ and data/malicious/"

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
	sudo python -m scbf.training.train_with_split
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
