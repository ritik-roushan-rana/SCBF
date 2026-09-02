# 🚀 START HERE - SCBF Project

**Welcome to the Supply Chain Behavioral Fingerprinting (SCBF) project!**

This is a clean, structured reorganization of your malicious package detection system.

---

## ⚡ Quick Navigation

| Document | Purpose |
|----------|---------|
| **→ [QUICKSTART.md](QUICKSTART.md)** | **Step-by-step first run guide** ← START HERE |
| [README.md](README.md) | Project overview and features |
| [MIGRATION.md](MIGRATION.md) | Old → new structure mapping |
| [docs/architecture.md](docs/architecture.md) | Technical deep-dive |
| [PROJECT_STRUCTURE.txt](PROJECT_STRUCTURE.txt) | File organization reference |

---

## 🎯 What Changed?

### Before (flat structure):
```
final/
├── install_monitor.py
├── tgn_encoder.py
├── itbg_constructor.py
├── train_v2.py
├── build_envelope_v2.py
├── cli.py
├── collect_dataset.py
└── data/
    ├── clean/
    └── malicious/
```

### After (structured package):
```
scbf_structured/
├── README.md                    ← Documentation
├── QUICKSTART.md               ← Your starting point
├── Makefile                     ← Common commands
├── requirements.txt
├── setup.py                     ← Installable package
│
├── scbf/                       ← Main code
│   ├── capture/                ← eBPF tracer
│   ├── models/                 ← TGN encoder
│   ├── training/               ← Training scripts
│   └── detection/              ← CLI scanner
│
├── scripts/                    ← Data collection
├── tests/                      ← Test suite
├── data/                       ← Training data
├── models/                     ← Saved weights
└── docs/                       ← Documentation
```

---

## 📋 Pre-Flight Checklist

Before running anything, verify your setup:

```bash
cd /Users/shield/Downloads/scbf_structured
sudo python3 verify_setup.py
```

This checks:
- ✓ Linux OS
- ✓ Python 3.11+
- ✓ Root/sudo access
- ✓ BCC installed
- ✓ Kernel headers
- ✓ PyTorch, NumPy
- ✓ Project structure
- ✓ All files present
- ✓ Imports working

---

## 🚀 Your First Run (5 minutes)

**If you already have data and models from the old structure:**

### Option A: Copy Existing Data & Models

```bash
# Copy your training data
cp -r /Users/shield/Downloads/final/data/clean/*.jsonl \
      /Users/shield/Downloads/scbf_structured/data/clean/

cp -r /Users/shield/Downloads/final/data/malicious/*.jsonl \
      /Users/shield/Downloads/scbf_structured/data/malicious/

# Copy your trained models (if you have them)
cp /Users/shield/Downloads/final/tgn_v2_best.pt \
   /Users/shield/Downloads/scbf_structured/models/ 2>/dev/null || true

cp /Users/shield/Downloads/final/envelope_v2.npy \
   /Users/shield/Downloads/scbf_structured/models/ 2>/dev/null || true

# Test a scan immediately
cd /Users/shield/Downloads/scbf_structured
sudo python -m scbf.detection.cli --package requests
```

**If starting fresh (no existing data):**

### Option B: Collect New Data

```bash
cd /Users/shield/Downloads/scbf_structured

# 1. Collect data (~30 min)
sudo make collect-data

# 2. Train model (~10 min)
sudo make train

# 3. Test a scan
sudo make scan PKG=requests
```

---

## 📚 Key Files to Know

### For Using SCBF:
- **`scbf/detection/cli.py`** - Main scanner
- **`models/tgn_v2_best.pt`** - Trained model
- **`models/envelope_v2.npy`** - Behavioral baseline

### For Training/Development:
- **`scbf/training/train.py`** - Training script
- **`scbf/training/build_envelope.py`** - Envelope builder
- **`scripts/collect_clean_data.py`** - Clean data collection
- **`scripts/collect_malicious_data.py`** - Malicious data collection

### For Understanding the System:
- **`docs/architecture.md`** - How everything works
- **`scbf/models/tgn_encoder.py`** - TGN implementation
- **`scbf/capture/install_monitor.py`** - eBPF tracer

---

## 🎓 Learning Path

1. **Beginner**: Read [QUICKSTART.md](QUICKSTART.md) and run a scan
2. **Intermediate**: Read [README.md](README.md) and collect your own data
3. **Advanced**: Read [docs/architecture.md](docs/architecture.md) and modify the TGN
4. **Expert**: Extend to new package ecosystems (npm, cargo)

---

## 🔧 Common Commands

```bash
# Verify setup
sudo python3 verify_setup.py

# Collect training data
sudo make collect-data
# or manually:
sudo python scripts/collect_clean_data.py
sudo python scripts/collect_malicious_data.py

# Train model
sudo make train
# or manually:
sudo python -m scbf.training.train
sudo python -m scbf.training.build_envelope

# Scan a package
sudo make scan PKG=requests
# or manually:
sudo python -m scbf.detection.cli --package requests

# Check model quality
sudo python scripts/check_distances.py

# Run tests
pytest tests/ -v

# Clean temp files
make clean
```

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| "Permission denied" | Run with `sudo` |
| "Cannot import bcc" | `sudo apt install bpfcc-tools python3-bpfcc` |
| "Invalid argument" (BPF) | `sudo apt install linux-headers-$(uname -r)` |
| "No events captured" | Check package installs: `pip install --target=/tmp/test <pkg>` |
| Import errors | `pip install -e .` from project root |

See [QUICKSTART.md](QUICKSTART.md#troubleshooting) for detailed fixes.

---

## 📊 Current Status

**Phase 1: ✅ Complete**
- Real eBPF capture working
- TGN encoder trained
- CLI scanner functional
- Behavioral envelope calibrated

**Phase 2: 🔄 In Progress**
- Malicious dataset integrated (99 samples)
- Contrastive loss training
- Distance correlation being addressed

**Phase 3: ⏳ Planned**
- CI/CD integration
- Mid-install kill-switch
- Network event capture
- Production deployment

---

## 📦 What's Included

- ✅ Full working code (capture, models, training, detection)
- ✅ 60+ clean package samples
- ✅ 99 malicious package samples  
- ✅ Trained model weights
- ✅ Complete documentation
- ✅ Test suite
- ✅ Makefile for common tasks
- ✅ Installable Python package

---

## 🎯 Next Steps

1. **Verify setup**: `sudo python3 verify_setup.py`
2. **Read quickstart**: [QUICKSTART.md](QUICKSTART.md)
3. **Run your first scan**: `sudo make scan PKG=requests`
4. **Explore architecture**: [docs/architecture.md](docs/architecture.md)
5. **Collect more data** or **tune the model**

---

## 💡 Pro Tips

- Always run with `sudo` (eBPF requires root)
- Use `Makefile` for common tasks (`make help`)
- Check `verify_setup.py` if anything breaks
- Read [MIGRATION.md](MIGRATION.md) for old/new command mappings
- Training data is in `data/`, models in `models/`
- All imports now work: `from scbf import TGNEncoder`

---

## 📞 Getting Help

1. Check [QUICKSTART.md](QUICKSTART.md) troubleshooting section
2. Review [docs/architecture.md](docs/architecture.md) for technical details
3. Look at [MIGRATION.md](MIGRATION.md) for old→new structure mapping
4. Run `sudo python3 verify_setup.py` to diagnose issues

---

**Ready? → [Open QUICKSTART.md](QUICKSTART.md) and begin!**

Good luck! 🚀
