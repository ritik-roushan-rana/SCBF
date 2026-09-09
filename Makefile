.PHONY: help install train build-envelope scan-trace scan-batch scan validate-data clean capture-live-benign recalibrate

help:
	@echo "SCBF - Supply Chain Behavioral Fingerprinting"
	@echo ""
	@echo "Setup:"
	@echo "  make install            Install dependencies (creates .venv)"
	@echo "  make validate-data      Validate dataset integrity"
	@echo ""
	@echo "Training & Envelope:"
	@echo "  make train              Train the hybrid TGN model (~30-60 min)"
	@echo "  make build-envelope     Build behavioral envelope from clean packages"
	@echo "  make evaluate           Evaluate trained model on train/val/test splits"
	@echo ""
	@echo "Detection (Scanning):"
	@echo "  make scan-trace TRACE=path/to/trace.jsonl    Scan existing trace file"
	@echo "  make scan-batch DIR=path/to/traces/          Batch scan a directory"
	@echo "  make scan PKG=requests                        Live scan (Linux + eBPF)"
	@echo ""
	@echo "Diagnostics:"
	@echo "  make diagnose           Run all diagnostic scripts on the dataset"
	@echo ""
	@echo "Calibration (fixes live-scan false positives on this host):"
	@echo "  make capture-live-benign  Capture live traces of known-clean packages"
	@echo "  make recalibrate          capture-live-benign + rebuild envelope"
	@echo ""
	@echo "Other:"
	@echo "  make clean              Remove cache files"
	@echo ""
	@echo "Workflow — first time (need to produce a model):"
	@echo "  1. make install"
	@echo "  2. make validate-data"
	@echo "  3. make train"
	@echo "  4. make build-envelope"
	@echo "  5. make scan-trace TRACE=<file>     (or  make scan PKG=<name>  on Linux)"
	@echo ""
	@echo "Workflow — already have a trained model (copied from elsewhere):"
	@echo "  1. make install"
	@echo "  2. place models/*.pt and models/envelope_v2*.* in models/"
	@echo "  3. make scan-trace / scan-batch / scan"

PY := $(shell if [ -f .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)

install:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt
	@echo ""
	@echo "✓ Installed to .venv/"
	@echo "  Activate with: source .venv/bin/activate"

validate-data:
	@echo "Validating dataset integrity..."
	$(PY) scripts/validate_dataset.py

train:
	@echo "Training HYBRID V2 model (TGN + statistical features)..."
	$(PY) -m scbf.training.train_hybrid_v2
	@echo ""
	@echo "✓ Training complete! Model saved to models/scbf_hybrid_v2.pt"
	@echo "  Next: make build-envelope"

build-envelope:
	@echo "Building Behavioral Envelope from clean packages..."
	$(PY) -m scbf.training.build_envelope
	@echo ""
	@echo "✓ Envelope built! Files saved in models/"
	@echo "  Next: make scan-trace TRACE=<file>"

evaluate:
	@echo "Evaluating model on train / val / test splits..."
	$(PY) -m scbf.training.evaluate
	@echo ""
	@echo "✓ Results saved to models/evaluation_results.json"

scan-trace:
	@if [ -z "$(TRACE)" ]; then \
		echo "Error: Trace path required."; \
		echo "Usage: make scan-trace TRACE=path/to/trace.jsonl"; \
		exit 1; \
	fi
	$(PY) -m scbf.detection.cli --trace $(TRACE)

scan-batch:
	@if [ -z "$(DIR)" ]; then \
		echo "Error: Directory required."; \
		echo "Usage: make scan-batch DIR=path/to/traces/"; \
		exit 1; \
	fi
	$(PY) -m scbf.detection.cli --batch $(DIR)

scan:
	@if [ -z "$(PKG)" ]; then \
		echo "Error: Package name required."; \
		echo "Usage: make scan PKG=requests"; \
		echo ""; \
		echo "Optional:"; \
		echo "  ARTIFACT=<path/URL/spec>   Pip artifact to install (defaults to PKG)"; \
		echo "  PYTHON=<path>              Python binary to install with (defaults to .venv)"; \
		echo ""; \
		echo "Note: Live scanning requires Linux + eBPF (python3-bpfcc, bpfcc-tools)."; \
		echo "On macOS, use 'make scan-trace' or 'make scan-batch' instead."; \
		exit 1; \
	fi
	@echo "Live scanning $(PKG) (requires Linux + eBPF)..."
	sudo -E $(PY) -m scbf.detection.cli --package $(PKG) \
		$(if $(ARTIFACT),--artifact $(ARTIFACT),) \
		$(if $(PYTHON),--python $(PYTHON),)

diagnose:
	@echo "Running diagnostic scripts..."
	@echo ""
	@echo "─── Trace length analysis ───"
	$(PY) scripts/diagnostics/check_length_confound.py
	@echo ""
	@echo "─── Rate feature ablation ───"
	$(PY) scripts/diagnostics/ablation_rate_normalized.py
	@echo ""
	@echo "─── Install success verification ───"
	$(PY) scripts/diagnostics/verify_install_success.py

capture-live-benign:
	@echo "Capturing live traces of known-clean packages on this host..."
	@echo "This calibrates the envelope to the local pip / Python / path layout."
	sudo -E ./scripts/capture_live_benign.sh

recalibrate: capture-live-benign build-envelope
	@echo ""
	@echo "✓ Envelope recalibrated for this host."
	@echo "  Live scans (make scan PKG=<pkg>) should now return ALLOW for clean packages."

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -f last_capture.jsonl
	rm -rf build/ dist/
	@echo "✓ Cleaned"
