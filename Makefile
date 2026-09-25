.PHONY: help install audit capture train evaluate scan clean

help:
	@echo "SCBF v2 - Supply Chain Behavioral Fingerprinting"
	@echo ""
	@echo "Pipeline (run in order):"
	@echo "  make install                      Create .venv and install deps"
	@echo "  make capture BENIGN=.. MALWARE=.. Collect traces (Linux + eBPF, root)"
	@echo "  make audit                        Leakage audit  <-- BEFORE TRUSTING ANY METRIC"
	@echo "  make train                        Train the hybrid TGN model"
	@echo "  make evaluate                     Metrics on train/val/test"
	@echo ""
	@echo "  make scan TRACE=path/to.jsonl     Score a single trace"
	@echo "  make clean                        Remove caches"
	@echo ""
	@echo "The audit step is not optional. The previous dataset had a"
	@echo "collection artifact (/dev/pts in 97.2% of benign, 0% of malicious)"
	@echo "that inflated F1 from ~52% to 92.31%. 'make train' refuses to run"
	@echo "on a dataset that fails the audit unless you pass FORCE=1."

PY := $(shell if [ -f .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)
TRACES ?= data/traces

install:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt
	@echo "\n✓ Installed. Activate with: source .venv/bin/activate"

capture:
	@if [ -z "$(BENIGN)" ] || [ -z "$(MALWARE)" ]; then \
		echo "Usage: sudo make capture BENIGN=data/raw/benign MALWARE=data/raw/malware"; exit 1; fi
	sudo $(PY) capture/collect_dataset.py --benign $(BENIGN) --malware $(MALWARE) \
		--out $(TRACES) --python $$(which python3) $(if $(LIMIT),--limit $(LIMIT),)

audit:
	$(PY) -m scbf.audit.leakage --traces $(TRACES)

train:
	@if [ "$(FORCE)" != "1" ]; then \
		$(PY) -m scbf.audit.leakage --traces $(TRACES) --strict || \
		{ echo ""; echo "REFUSING TO TRAIN: dataset failed the leakage audit."; \
		  echo "Fix the capture, or re-run with FORCE=1 if you know what you are doing."; exit 1; }; \
	fi
	$(PY) -m scbf.training.train --traces $(TRACES)

evaluate:
	$(PY) -m scbf.training.evaluate --traces $(TRACES)

scan:
	@if [ -z "$(TRACE)" ]; then echo "Usage: make scan TRACE=path/to/trace.jsonl"; exit 1; fi
	$(PY) -m scbf.detection.cli --trace $(TRACE)

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "✓ Cleaned"
