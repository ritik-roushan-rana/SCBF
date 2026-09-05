# SCBF Repository Structure

Clean and organized structure for the SCBF project.

## Root Directory

```
SCBF/
├── README.md              # Main documentation
├── Makefile              # Build and run commands
├── requirements.txt      # Python dependencies
├── setup.py             # Package setup
├── verify_setup.py      # Verify installation
├── monitor.sh           # eBPF monitoring script
├── copy_dataset.sh      # Dataset helper
│
├── data/                # Dataset (gitignored)
│   └── zenodo_13746167/
│       ├── benign/traces/    (959 files)
│       └── malware/traces/   (385 files)
│
├── scbf/               # Main package
│   ├── models/         # TGN encoder, ITBG constructor
│   ├── training/       # Training scripts
│   ├── detection/      # Detection CLI
│   ├── preprocessing/  # Data preprocessing
│   └── utils/          # Utilities
│
├── models/             # Trained models (gitignored)
│   ├── tgn_v2_best.pt
│   ├── envelope_v2.npy
│   └── checkpoints/
│
├── scripts/            # Utility scripts
│   ├── collect_zenodo.py       # Data collection
│   ├── validate_dataset.py     # Dataset validation
│   ├── aggregate_jsonl.py      # Data aggregation
│   ├── check_distances.py      # Distance analysis
│   ├── quick_eval.py           # Quick evaluation
│   ├── find_best_threshold.py  # Threshold optimization
│   └── helpers/                # Helper scripts
│       ├── check_progress.sh
│       ├── check_training.sh
│       ├── prepare_for_colab.sh
│       └── retrain_improved.sh
│
├── notebooks/          # Jupyter/Colab notebooks
│   ├── Colab_Training_Complete.ipynb
│   └── SCBF_Training_Colab.ipynb
│
├── docs/              # Documentation
│   ├── README.md
│   ├── architecture.md
│   ├── DATASET_READY.md
│   ├── MONITOR_USAGE.md
│   ├── TRAINING_DATA_FORMAT.md
│   ├── COLAB_INSTRUCTIONS.md
│   ├── HOW_TO_UPLOAD_COLAB.md
│   ├── training_history/       # Training docs
│   │   ├── ACCURACY_FIX.md
│   │   ├── TRAINING_READY.md
│   │   └── TRAINING_V3_STATUS.md
│   └── restructuring/          # Setup guides
│
├── experiments/       # Experimental code
│   ├── build_envelope.py
│   ├── capture_v2.py
│   └── collect_large_dataset.py
│
└── tests/            # Test files
```

## Key Files

### Root Level
- **README.md** - Main project documentation
- **Makefile** - Quick commands (train, scan, validate)
- **monitor.sh** - eBPF monitoring (Linux only)
- **requirements.txt** - Python dependencies

### Core Package (scbf/)
- **models/tgn_encoder.py** - TGN model implementation
- **models/itbg_constructor.py** - Graph constructor
- **training/train_with_split.py** - Training script (improved)
- **detection/cli.py** - Detection CLI

### Scripts
- **collect_zenodo.py** - Automated data collection
- **validate_dataset.py** - Dataset validation
- **quick_eval.py** - Fast model evaluation
- **find_best_threshold.py** - Threshold optimization

### Notebooks
- **Colab_Training_Complete.ipynb** - Complete Colab training
- **SCBF_Training_Colab.ipynb** - Alternative Colab notebook

### Documentation
- **COLAB_INSTRUCTIONS.md** - How to train on Colab
- **MONITOR_USAGE.md** - Monitor & collection guide
- **DATASET_READY.md** - Dataset status
- **TRAINING_DATA_FORMAT.md** - Data format requirements

## What's Gitignored

```
data/zenodo_13746167/*/traces/*.jsonl  # Dataset files (2.6 GB)
data/zenodo_13746167/*/data/*.jsonl    # Aggregated data
models/*.pt                            # Trained models
models/*.npy                           # Envelopes
models/checkpoints/*.pt                # Training checkpoints
*.log                                  # Log files
*.pid                                  # Process IDs
__pycache__/                           # Python cache
.venv/                                 # Virtual environment
```

## Usage

### Local Training
```bash
make train-split         # Train model
make validate-data       # Validate dataset
make scan PKG=requests   # Scan package
```

### Colab Training
1. Upload notebook: `notebooks/Colab_Training_Complete.ipynb`
2. Enable GPU
3. Upload data or use Google Drive
4. Run all cells

### Evaluation
```bash
python scripts/quick_eval.py              # Quick test
python scripts/find_best_threshold.py     # Find optimal threshold
python -m scbf.training.evaluate          # Full evaluation
```

## Clean Structure Benefits

✅ **Root is clean** - Only essential files  
✅ **Organized** - Scripts, docs, notebooks in separate folders  
✅ **Clear purpose** - Each directory has specific role  
✅ **Maintainable** - Easy to find what you need  
✅ **Professional** - Ready for collaboration  

## File Counts

- **Root files:** 8 (core only)
- **Scripts:** 10 (organized in scripts/)
- **Docs:** 15+ (organized in docs/)
- **Notebooks:** 2 (in notebooks/)
- **Core package:** ~15 Python files
- **Total:** Clean and organized!
