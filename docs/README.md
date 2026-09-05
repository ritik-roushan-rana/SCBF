# SCBF Documentation

## Quick Links

### Getting Started
- **[../README.md](../README.md)** - Main project README (start here!)
- **[restructuring/SIMPLE_SETUP.md](restructuring/SIMPLE_SETUP.md)** - Quick setup guide for placing your dataset

### Architecture & Design
- **[architecture.md](architecture.md)** - Technical architecture deep-dive
- **[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)** - Project organization

### Dataset Documentation
- **[../data/README.md](../data/README.md)** - Event format specifications
- **[restructuring/DATASET_PLACEMENT.md](restructuring/DATASET_PLACEMENT.md)** - How to place your dataset
- **[restructuring/FINAL_STRUCTURE.md](restructuring/FINAL_STRUCTURE.md)** - Directory structure explanation

## Documentation Structure

```
docs/
├── README.md (you are here)
│
├── architecture.md              # System architecture
├── PROJECT_STRUCTURE.md         # Code organization
│
├── restructuring/               # Dataset & repository setup
│   ├── SIMPLE_SETUP.md          # Quick start (⭐ start here)
│   ├── DATASET_PLACEMENT.md     # Detailed placement guide
│   ├── FINAL_STRUCTURE.md       # Directory structure
│   ├── DATASET_PREPARATION_GUIDE.md  # Full preparation workflow
│   ├── REPOSITORY_ANALYSIS.md   # Technical analysis
│   └── RESTRUCTURING_COMPLETE.md     # What changed
│
├── 00_START_HERE.md             # Legacy quick start
└── IMPLEMENTATION_COMPLETE.md   # Legacy implementation notes
```

## Which Document to Read?

### "I just want to use SCBF with my dataset"
→ [restructuring/SIMPLE_SETUP.md](restructuring/SIMPLE_SETUP.md)

### "I need to understand the event format"
→ [../data/README.md](../data/README.md)

### "I want to understand how SCBF works"
→ [architecture.md](architecture.md)

### "I want to collect my own dataset"
→ [restructuring/DATASET_PREPARATION_GUIDE.md](restructuring/DATASET_PREPARATION_GUIDE.md)

### "I want to see what changed in the repository"
→ [restructuring/RESTRUCTURING_COMPLETE.md](restructuring/RESTRUCTURING_COMPLETE.md)

## External References

- **GitHub**: https://github.com/ritik-roushan-rana/SCBF
- **Datadog Malicious Packages**: https://github.com/DataDog/malicious-software-packages-dataset
- **TGN Paper**: Rossi et al. "Temporal Graph Networks for Deep Learning on Dynamic Graphs"

---

**For most users**: Start with [restructuring/SIMPLE_SETUP.md](restructuring/SIMPLE_SETUP.md) to place your dataset and train the model.
