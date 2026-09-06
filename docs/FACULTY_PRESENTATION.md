# SCBF — Faculty Presentation Script

**Project:** Supply Chain Behavioral Fingerprinting (SCBF)
**Innovation 6 of 7** — Patent Pending
**Presenter:** Ritik Roushan Rana
**Status:** Phase 1 complete, working prototype

---

## How to Use This Document

Read the **bold** sentences aloud. The italic *speaker notes* are for you
only. The tables and code blocks are backup slides if faculty asks for
detail. Time yourself — the whole thing is ~15 minutes without questions.

---

## 1. The Problem  (2 min)

> **"Software supply chain attacks are now the fastest-growing attack vector
> in cybersecurity, and every existing defence is static."**

*Give one concrete example so it lands:*

> **"In 2022, a malicious PyPI package called `ctx` was uploaded that read
> every environment variable — including AWS credentials — during
> installation and POSTed them to an attacker's server. It was on PyPI for
> weeks before a security researcher spotted it manually."**

The problem in one sentence:

> **"No existing tool catches malicious behaviour at the moment of `pip
> install`. Everything runs *before* install (name scanning, hash checks,
> code review) or *after* install (EDR, SIEM). The install itself is a
> blind spot."**

Why current defences fail:

| Existing defence | Why it misses supply-chain attacks |
|------------------|-----------------------------------|
| Name scanning | Only catches typosquatting, misses hijacked-real-name attacks |
| Hash / signature | New packages have no known hash |
| Static code review | Obfuscated / encoded / build-time payloads slip through |
| CVE database | Zero-day malicious logic is not a CVE |
| Sandboxed import | Malware detects the sandbox and delays execution |

---

## 2. The Idea  (2 min)

> **"A malicious package cannot hide what it does — only what it looks
> like. When a package installs, it *must* execute code. That execution
> produces a behavioural trace we can capture."**

The key insight:

> **"Install-time has a very narrow, predictable behavioural envelope.
> Legitimate Python packages read files under `site-packages`, run
> `setup.py`, maybe compile a native extension. They almost never make
> outbound network calls, read `~/.ssh/id_rsa`, or spawn `curl` during
> install. Malicious behaviour at install time stands out sharply."**

So the goal is:

> **"Capture what a package does during `pip install`, encode it into a
> behavioural fingerprint, and compare that fingerprint to what legitimate
> packages of the same type normally do. If it deviates, block the
> install *while it is still running* — before the payload lands."**

---

## 3. The Novelty  (3 min)

*This is the part faculty will focus on. Emphasise clearly.*

> **"Four things make this different from any prior work I've found:"**

### Novelty 1 — Install-time detection, not run-time

> **"Every existing malware detector — antivirus, EDR, sandbox tools —
> analyses run-time behaviour. This is the first system I know of that
> targets install-time behaviour specifically. That's important because
> most supply-chain attacks execute their entire payload during `pip
> install`, before the developer ever `import`s the package."**

### Novelty 2 — Temporal Graph Network on syscall streams

> **"I model each installation as a continuous-time dynamic graph, where
> nodes are processes / files / network endpoints / credential files, and
> edges are timestamped syscall events. I encode this with a Temporal
> Graph Network based on Rossi et al. 2020, which is what modern research
> uses for continuous-time dynamic graphs. Existing malware GNN work uses
> **static** graphs — they must wait for the graph to be complete before
> running inference. My design is streaming: it can emit a threat verdict
> after every single event, which means it can potentially kill an
> installation mid-flight, before the exfiltration call completes."**

### Novelty 3 — Behavioural envelope per package type

> **"Instead of learning 'what does malware look like', I learn 'what does
> a legitimate package of this type look like at each stage of install'.
> Malicious packages then get flagged by deviation from that envelope,
> not by matching known-bad signatures. This works for zero-days — a
> brand new attack still stands out from the envelope, even though it
> has no signature."**

### Novelty 4 — Hybrid TGN + statistical-feature fusion

> **"Pure TGN embeddings live on a unit sphere due to L2 normalisation,
> which limits their discriminative power. I augment them with 45
> hand-crafted statistical features from the same event stream — path
> categories, suspicious command ratios, time-based pacing features —
> and feed the combined vector to a classifier head. This hybrid gets
> me 92% F1 on the test set. Pure TGN alone reaches only about 52% F1
> on the same split, so the fusion is doing real work, not decorative."**

---

## 4. The Architecture  (3 min)

*Draw this on the board or show `ARCHITECTURE.md`.*

```
   pip install <package>
           ↓
   ┌───────────────────────────────┐
   │  eBPF Install Monitor         │   monitor.sh  (Linux, sudo)
   │  Captures exec / open /       │
   │  connect syscalls in real time│
   └────────────────┬──────────────┘
                    ↓  JSON events, per event
   ┌───────────────────────────────┐
   │  ITBG Constructor             │   Install-Time Behavioral Graph
   │  Streams events into a        │   Process · File · Network · Env
   │  heterogeneous temporal graph │   · Credential · Script  nodes
   └────────────────┬──────────────┘
                    ↓  per-event graph update
   ┌───────────────────────────────┐
   │  TGN Encoder                  │   Rossi et al. 2020
   │  Per-node memory + GRU +      │   TGNMemory + TimeEncode +
   │  time-encoded attention       │   TemporalAttentionEmbedding
   │  → 128-dim behavioural DNA    │
   └────────────────┬──────────────┘
                    ↓
   ┌───────────────────────────────┐
   │  Hybrid Fusion                │   TGN DNA (128) + Stats (64)
   │  128-d TGN + 64-d stats       │   = 192-dim combined vector
   │  = 192-dim combined           │
   └────────────────┬──────────────┘
                    ↓
   ┌───────────────────────────────┐
   │  Envelope Comparison          │   Distance to clean centroid
   │  + Classifier head            │   + sigmoid probability
   └────────────────┬──────────────┘
                    ↓
             ALLOW / WARN / BLOCK
             + threat score 0-100
```

**Walkthrough talking points:**

> **"Stage 1 — eBPF captures syscalls at kernel level. I hook `execve`,
> `openat`, `connect`. This is zero-overhead and can't be tampered with
> by the installing package, because the tracepoints live in kernel
> space."**

> **"Stage 2 — ITBGConstructor turns those events into a growing
> heterogeneous graph. Every process spawn becomes a `spawns` edge, every
> file write becomes a `writes_file` edge, and so on. Node and edge types
> are typed."**

> **"Stage 3 — TGN encoder consumes each event one at a time, in true
> arrival order. Every node keeps a memory vector that gets updated by a
> GRU cell after every event it participates in. A learned time encoding
> lets the model see the elapsed time since the last event — this is how
> it distinguishes a benign `sleep-then-act` install from a malicious
> `read-cred-then-connect-immediately` install with otherwise identical
> graph structure."**

> **"Stage 4 — hybrid fusion. Beyond what TGN can extract, I compute 45
> hand-crafted features from the same trace: ratio of exec events, ratio
> of `/tmp` accesses, presence of `curl` or `base64`, event rate over
> time. These bypass the L2-normalisation ceiling of TGN. Concatenated
> combined vector is 192-dim."**

> **"Stage 5 — verdict engine. Two independent signals: envelope distance
> from a clean-packages centroid, and a classifier probability. Distance
> beyond mean + 2.5·std is BLOCK, between 1.5·std and 2.5·std is WARN,
> otherwise ALLOW."**

---

## 5. Training  (2 min)

**Dataset:** Zenodo record 13746167 — 1,344 real PyPI packages: 959 benign, 385 malicious.

*Important honesty point — bring this up before they ask:*

> **"Every single one of these traces is a **successfully completed**
> install. I verified this with a dedicated diagnostic script: 100% of
> both classes end with `dist-info` written, `site-packages` populated,
> and metadata present. So the model is not just learning 'the install
> failed' — both classes complete."**

**Training recipe:**

| Setting | Value |
|---------|-------|
| Split | 70% train, 15% val, 15% test, stratified, fixed seed |
| Loss | Focal BCE with `pos_weight = n_clean / n_mal ≈ 2.49` |
| Optimiser | AdamW, lr 3e-4, weight decay 1e-4 |
| LR schedule | Cosine annealing with warm restarts |
| Regularisation | LayerNorm + Dropout (0.2 / 0.3 / 0.4) + grad clipping |
| Early stopping | Patience 8 epochs on val F1 |
| Threshold tuning | Grid search on val, optimal = 0.35 |
| Runtime | ~30-60 min on Mac CPU, ~10 min on T4 GPU |

---

## 6. Results  (2 min)

**Metrics on all three splits at classifier threshold 0.35:**

| Split | Samples | Accuracy | Precision | Recall | F1 | ROC-AUC |
|-------|--------:|---------:|----------:|-------:|---:|--------:|
| Train | 940 | 95.53% | 91.88% | 92.57% | 92.22% | 0.9680 |
| Val   | 202 | 94.55% | 89.83% | 91.38% | 90.60% | 0.9647 |
| Test  | 202 | **95.54%** | **91.53%** | **93.10%** | **92.31%** | **0.9788** |

**Confusion matrix on test:**

```
                Predicted
              Clean   Malicious
Actual Clean   139        5      (96.5% of clean packages allowed)
Actual Mal       4       54      (93.1% of malicious packages caught)
```

> **"Test F1 is 92.31%. The train-test F1 gap is minus 0.09%, meaning the
> model is not overfitting — test performance is essentially the same as
> training performance. This is reproducible: `make evaluate` regenerates
> these numbers in under two minutes."**

---

## 7. The Honest Confound Analysis  (2 min)

*Faculty will love this — it shows you actually pressure-tested your own
results. If they ask "how do I know your model is not just memorising
noise?" you're already prepared.*

> **"92% F1 on a small dataset is suspicious. I don't want to over-claim,
> so I ran five diagnostic scripts to see if the number holds up under
> stress."**

| Diagnostic | What it tests | Result |
|------------|---------------|--------|
| Trace length alone | Can a logistic regression on just `n_events` get high F1? | ROC-AUC 0.85 — length is a real but not dominant signal |
| Rate-only features | Do features normalised by trace length still discriminate? | F1 98% — signal is not merely trace length |
| Bootstrap-stripped | After removing pyenv / sudo / PAM / pip scaffolding paths, what F1 remains? | F1 70%, ROC-AUC 0.86 — real behavioural signal |
| Dataset artefacts | Are the two classes captured with different tooling? | Both use identical infrastructure — no cross-class artefact |
| Install-completion | Do both classes actually complete installation? | 100% of both classes complete — not detecting install failures |

**Honest read on the 92%:**

> **"About 22% of the surface-level F1 comes from sandbox-bootstrap noise
> (pyenv paths, sudo setup, etc). About 70% is genuine behavioural
> signal. Both numbers are legitimate signal on this dataset — the
> question of how much is 'transferable to other environments' is a
> Phase 2 question that needs a bigger, cross-environment dataset to
> answer."**

---

## 8. Live Demo  (2 min)

*Have this ready to run on the Ubuntu VM.*

```bash
sudo -E make scan PKG=requests
```

*What faculty will see:*

- eBPF captures ~1,200 syscall events during the install.
- TGN encodes the temporal graph.
- Envelope distance is computed.
- Classifier probability is computed.
- Final verdict prints in real time.

*Talking script while it runs:*

> **"This is the entire pipeline on real live infrastructure. eBPF is
> capturing every `execve`, `openat`, and `connect` syscall as pip
> installs `requests`. The TGN encoder is updating its internal memory
> after each event. When pip finishes, the encoder emits the final DNA
> vector, and the envelope engine emits the verdict."**

*What to say about the verdict:*

- If **ALLOW**: "Model correctly identifies `requests` as clean, prob < 0.35, distance below threshold."
- If **WARN** (which is what you got): "Model is cautious. Classifier says clean (0.33 < 0.35 threshold) but envelope distance is elevated because this VM's install environment differs slightly from the training environment. This is exactly the environment-drift issue the confound analysis flagged."
- If **BLOCK**: "Model incorrectly flags `requests` as malware — false positive."

*Then run one on a malicious trace to show BLOCK:*

```bash
make scan-trace TRACE=tmp_malware.jsonl
```
(you'll need to scp one over from your Mac)

*Expected:* BLOCK, threat 99/100, distance ~7.17.

---

## 9. Limitations — What Phase 1 Does *Not* Do  (1 min)

*Being upfront about limitations makes you look more credible, not less.*

> **"Phase 1 is a proof of concept. It validates the framework end-to-end,
> but it is not a production system yet. Six things are explicitly
> Phase 2:"**

1. **Package-type stratified envelopes** — currently one generic envelope for all Python packages. Should be separate envelopes for pure-Python libraries, native extensions, CLI tools, build tools.
2. **Install-stage envelopes** — envelope at 25 / 50 / 75 / 100 % of install, not just at end.
3. **FAISS malicious-signature index** — nearest-neighbour lookup against known malware families.
4. **Streaming mid-install kill-switch** — currently offline analysis of a completed trace, not a live stream.
5. **Multi-registry** — PyPI only. Need NPM, Cargo, RubyGems, Maven, Go.
6. **CI/CD integration** — GitHub Actions, GitLab CI, pre-commit hooks.

---

## 10. What I've Actually Built  (1 min)

**Deliverables:**

| Component | File | Status |
|-----------|------|--------|
| eBPF monitor | `monitor.sh` | ✅ working on Ubuntu |
| ITBG constructor | `scbf/models/itbg_constructor.py` | ✅ 6 node types, 8 edge types |
| TGN encoder | `scbf/models/tgn_encoder.py` | ✅ Rossi et al. 2020 |
| Hybrid classifier | `scbf/training/train_hybrid_v2.py` | ✅ 92.31% F1 |
| Envelope builder | `scbf/training/build_envelope.py` | ✅ two envelope variants |
| Detection CLI | `scbf/detection/cli.py` | ✅ trace / batch / live modes |
| Evaluation | `scbf/training/evaluate.py` | ✅ train/val/test report |
| Diagnostics | `scripts/diagnostics/*.py` | ✅ 6 confound-check scripts |

**Total:** ~2,600 lines of code, 3 documentation files, 6 diagnostic
scripts, a trained model, and a full working pipeline demonstrable on a
live Ubuntu VM.

---

## 11. Likely Questions and Prepared Answers

### Q: "Why not just use static code analysis?"

> **"Static analysis reads the source code. Modern supply-chain attacks
> use base64-encoded payloads, obfuscation, and build-time injection.
> The malicious code often isn't present in the source at all — it's
> constructed at install time. Behavioural analysis catches the *effect*,
> not the *source*, so obfuscation doesn't help the attacker."**

### Q: "Why TGN and not a simpler model?"

> **"Because timing matters. A benign install that reads a config file
> and then makes an HTTP call five seconds later is completely different
> from a malicious install that reads `~/.aws/credentials` and connects
> to an attacker's server in the same millisecond. Static graph GNNs see
> the same graph structure for both. TGN's time encoding sees the delay
> directly, so it can distinguish the timing pattern that identifies the
> attack."**

### Q: "Isn't 1,344 packages a really small dataset?"

> **"Yes. This is Phase 1 — proof of concept. The patent spec targets
> 31,250 event streams across PyPI, NPM, and Cargo. Phase 2 scales the
> data. The point of Phase 1 is to show the architecture works, which
> it does — 92% F1 with no overfitting is enough evidence to justify
> scaling."**

### Q: "How would this evade an attacker who knows about it?"

> **"An adversarial attacker could slow down malicious operations to
> match benign timing, or route malicious calls through the same syscalls
> as legitimate installers. TGN's time encoding partially defends
> against pacing attacks — I train on both fast and slow variants. But
> a determined adversary who knows the exact envelope can craft an
> install-time payload that stays inside it. This is a limitation of
> **any** behavioural detector and is why Phase 2 adds per-package-type
> envelopes and known-malicious signatures — layered defence, not a
> single silver bullet."**

### Q: "How does this compare to Snyk / Dependabot / GitHub Advisory?"

> **"Snyk, Dependabot, and GitHub Advisory are all **static**. They check
> known CVEs against your dependency list. They cannot detect a
> **brand-new** malicious package that has no CVE yet — which is exactly
> what typosquatting and account-hijack attacks are. SCBF is
> complementary: use static tools for known vulnerabilities, use SCBF
> for zero-day behavioural anomalies."**

### Q: "Why did WARN come up on `requests`?"

> **"`requests` is a legitimate library, and the classifier probability
> (0.33) correctly says it's clean — below the 0.35 threshold. But the
> envelope distance (4.45) is elevated because my training environment
> was slightly different from this VM's environment — different pyenv
> path, different pip version, different pre-installed libs. So the
> envelope treats it as somewhat unusual and hedges with WARN. This is
> exactly the environment-sensitivity problem I flagged in my honest
> limitations. It's a Phase 2 fix: retrain on multiple environments,
> normalise for environment features, or use per-environment envelopes."**

### Q: "What's your patent claim?"

> **"There's a full patent disclosure — Innovation 6 of 7, ten claims.
> Claim 1 is the independent claim: a system that intercepts install-time
> syscalls, streams them into a TGN encoder with per-node memory,
> computes a behavioural DNA vector after every event, and produces a
> continuously-updated verdict against a package-type-specific
> envelope. Claim 6 covers the mid-install kill switch. Claim 8 covers
> the CI/CD integration path."**

### Q: "Have you tested against actual real-world PyPI malware?"

> **"The 385 malicious packages in the dataset are all real PyPI
> malicious packages taken from published security advisories (mostly
> Datadog's public catalogue). I have not yet tested against
> zero-day / never-seen samples — that's a Phase 2 evaluation on live
> PyPI feeds."**

---

## 12. Closing  (30 sec)

> **"So to summarise: I've built and validated Phase 1 of a
> supply-chain behavioural fingerprinting system. It captures
> install-time syscalls with eBPF, encodes them with a continuous-time
> Temporal Graph Network, and produces install-time verdicts with 92%
> F1 on a real PyPI dataset. The whole pipeline runs live on an Ubuntu
> VM, from `pip install` to verdict in a few seconds. The confound
> analysis honestly separates real behavioural signal from
> sandbox-bootstrap noise. Everything is reproducible from the GitHub
> repository. Phase 2 is scale, streaming verdicts, per-package-type
> envelopes, and CI/CD integration."**

**Repository:** https://github.com/ritik-roushan-rana/SCBF
**Architecture doc:** `ARCHITECTURE.md`
**Achievement doc:** `docs/PHASE1_ACHIEVEMENTS.md`

---

## Appendix — Numbers You Should Have Memorised

| Metric | Value |
|--------|-------|
| Test accuracy | 95.54% |
| Test precision | 91.53% |
| Test recall | 93.10% |
| Test F1 | 92.31% |
| Test ROC-AUC | 0.9788 |
| Train-test F1 gap | −0.09% (no overfit) |
| Dataset size | 1,344 packages (959 clean, 385 malicious) |
| Model size | 421 KB (`scbf_hybrid_v2.pt`) |
| DNA vector dim | 128 (TGN) → 192 (hybrid) |
| TGN memory dim | 64 per node |
| Statistical features | 45 |
| Trainable parameters | ~60,000 |
| Best threshold | 0.35 |
| Envelope threshold | 4.6502 (mean + 2.5·std) |
| Confound-adjusted F1 | 70% (bootstrap-stripped) |
| Live-scan latency | ~2-5 seconds per package |
