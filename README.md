# AMD-Agent: Autonomous Malware Detection Agent

AMD-Agent is an autonomous, LLM-assisted continual-learning system for **Windows PE malware detection**. It continuously collects malware and benign samples from live sources, validates and featurizes them using safe static analysis, monitors **concept drift**, and updates a **LightGBM** classifier using **replay-based retraining**. Each model update is evaluated with a **strict temporal holdout** to enable reliable before/after comparisons.

**Safety:** AMD-Agent ingests live, weaponized binaries. **Do not execute downloaded samples.** Run only in Docker or an isolated malware-analysis VM.

## Quickstart (Docker)

### 1) Create `.env`

Create `.env` from the example:

```powershell
copy .env.example .env
```

Required:

```env
MALWAREBAZAAR_AUTH_KEY=your-auth-key
```

Common optional:

```env
AMD_OLLAMA_BASE_URL=http://localhost:11434
AMD_OLLAMA_MODEL=llama3.1:8b
OTX_API_KEY=...
GITHUB_TOKEN=...
MALSHARE_API_KEY=...
```

### 2) Build and run

Start Docker Desktop first.

Build:

```powershell
docker compose build
```

Run a single pass:

```powershell
docker compose run --rm amd-agent python -m src.graph --once
```

Run the full stack (preflight → conditional bootstrap → daemon loop):

```powershell
docker compose up --force-recreate
```

**Persistence:** Docker persists DB, models, logs, and figures under `./data`.

## What we aim to achieve

- **No fixed dataset**: build and maintain a living corpus from real-world sources.
- **Continual adaptation**: detect drift and retrain to recover performance over time.
- **Reliable update evaluation**: compare *previous vs updated* models on the *same* strict chronological holdout excluded from training.
- **LLM as a sidecar**: use Ollama for best-effort semantic assistance without making correctness depend on LLM output.

## Tech stack & tooling

- **Workflow orchestration**: LangGraph (`langgraph`).
- **Static PE parsing**: `pefile`.
- **Feature representation**: EMBER-inspired **2304-dimensional** static PE vector (fixed-width).
- **Classifier**: LightGBM (with Optuna-driven hyperparameter tuning during retrain updates).
- **Drift detection**: River’s ADWIN (streaming drift detection) + windowed feature-shift checks.
- **Continual learning**: MADAR-inspired diversity-aware replay to mitigate catastrophic forgetting.
- **Evaluation**: TESSERACT-style chronological evaluation (reduces temporal leakage).
- **Persistent storage**: SQLite (sample lifecycle, provenance, yields).
- **LLM sidecar**: Ollama (local) for CTI filtering, drift explanations, and workflow assistance.

## Feature engineering & selection (high-level)

Each validated PE file is projected into a fixed **2304-d** static vector inspired by EMBER (fast, deterministic, and execution-free). At a high level we combine:

- **Scalars (128d)**: PE header fields (DOS/COFF/Optional), section counts/sizes/entropy stats, import/export counts, file size/overlay indicators, string/URL/path/registry counters, Authenticode + parse flags, plus optional disassembly counters when Capstone is available.
- **Byte histogram (256d)**: normalized frequency of each byte value (0–255).
- **Byte-entropy histogram (256d)**: joint histogram of entropy buckets × high‑nibble buckets (captures packed/encrypted regions).
- **Printable strings (96d)**: distribution of printable ASCII characters (with additional string stats included in Scalars).
- **Section hash (128d)**: hashed section tokens (name + characteristics), weighted by section size.
- **Import hash (1024d)**: hashed bag-of-imports over (DLL, API) names (capability surface).
- **Export hash (256d)**: hashed export symbols (module surface / loader-like behavior).
- **Opcode features (160d, optional)**: disassembly-derived opcode/control-flow pattern counters (when Capstone exists).

To keep training fast, we perform a simple **feature selection** step before fitting LightGBM:

- **Rank**: train a small XGBoost model on the training split and read `feature_importances_` (one score per feature).
- **Select**: sort by importance and keep the top **K** features (in our report runs, **K = 384**).
- **Train**: fit LightGBM only on those selected features; the full 2304-d vector is still extracted for drift monitoring and logging.

## Academic inspirations / related work

This project is directly inspired by the following works/tools (see `amd_agent_report/references.bib`):

- **EMBER** (static PE feature methodology): Anderson & Roth, 2018.
- **TESSERACT** (chronological evaluation to reduce temporal leakage): Pendlebury et al., 2019.
- **MADAR** (replay for continual learning in malware): Rahman et al., 2025.
- **ADWIN / River** (streaming drift detection): River documentation.
- **MalwareBazaar** (live malware source): abuse.ch.
- **pefile** (safe static PE parsing): Carrera.
- **LangGraph** (graph-based agent orchestration): LangChain.
- **Ollama** (local LLM runtime): Ollama project.
- **OTX** (CTI pulses): AlienVault OTX.

## How the workflow works

At a high level, AMD-Agent runs as a LangGraph state machine with a closed-loop feedback controller:

```text
START
  -> SourceSelector (balance-aware routing; optional LLM assistance)
  -> SourceDiscovery (live providers, CTI fallbacks)
  -> BinaryFetch
  -> DataValidation (hard gates; quarantine corrupted)
  -> FeatureExtraction (2304-d static vector)
  -> DriftMonitor (ADWIN + windowed shift checks)
      -> no drift: ClassifierInference -> EvaluationGate -> END
      -> drift: ExplainDriftContext -> ModelRetrain -> EvaluationGate -> END
```

### Dataset balancing (SQLite 50/50 controller)

To keep learning stable, AMD-Agent maintains an approximately **1:1 malware/benign** corpus. On each collection run it counts **active** malware vs benign samples in SQLite and then downloads more of whichever class is behind (target ratio **1:1** with a tolerance of **±10%**) using malware feeds (e.g., MalwareBazaar) or benign feeds (Sysinternals, GitHub, Benign‑NET) until the dataset stays balanced.

### State management (short-term vs long-term)

- **Per-run state (`AgentState`)**: a fresh run state each pass (discovered candidates, file paths, features, routing flags like `drift_detected`). The graph clears these fields between runs to prevent stale batch data from leaking forward.
- **Persistent state (outside LangGraph)**:
  - **SQLite** stores sample lifecycle (pending/active/corrupted), labels, provenance, extracted features, predictions, and ingest timestamps.
  - The **LightGBM model** is persisted (Joblib).
  - The **ADWIN drift detector state** is persisted (Joblib).
  - Evaluation and drift/model-update logs are written under `data/` as JSONL.

### Control loop: collection, learning, and evaluation gates

- **Collection gate**: balances malware vs benign volumes based on SQLite counts and recent provider yields (cooldowns for low-yield providers).
- **ML gate**:
  - **Drift detection** uses ADWIN over section entropy plus windowed feature-shift checks.
  - If drift is detected, the graph routes to explanation and replay-based retraining.
  - If no drift is detected, the graph routes to inference.
- **Evaluation gate**:
  - Runs **chronological (TESSERACT-style)** evaluation periodically, and after drift/retrain events.
  - After a successful model update, AMD-Agent evaluates **previous vs updated** on the same **strict temporal holdout** excluded from training, recording before/after deltas.

### Continual learning loop (cold start → MADAR retrain → TESSERACT eval)

- **Phase 1 — Cold start (bootstrap)**: before a production model exists (or before it is “ready”), the agent collects balanced malware+benign, extracts 2304-d features into SQLite, and once it has enough samples (default **≥100 malware** and **≥100 benign** with features) it trains the first LightGBM model. This cold-start training uses a **stratified random** split (**70% train / 15% validation / 15% test**) to enforce a fair mix and to calibrate the decision threshold on validation; the resulting `model.pkl` is then used for inference on subsequent runs.
- **Phase 2 — MADAR retrain loop (adaptation)**: malware is non-stationary, so when **drift fires** or the system accumulates enough new/untrained samples (e.g., **≥50**), it retrains the production LightGBM model using a MADAR-style replay buffer. A strict “future” slice (newest **15%**) stays out of training, and up to **3,000** replay samples help prevent catastrophic forgetting; the previous model is archived and a new `model.pkl` becomes production.
- **Phase 3 — TESSERACT evaluation (report-only)**: periodically (e.g., every **10** steady runs) and after retrains, AMD-Agent runs a chronological evaluation that trains a **temporary** model on the oldest data and tests on the newest slice (**70% oldest train / 15% next validate / 15% newest test**, sorted by ingestion time). This produces an “honest grade” (Accuracy/FPR/etc.) and logs/plots **without** modifying production `model.pkl`.

### Drift detection (windowed feature shift)

In addition to ADWIN (entropy stream), AMD-Agent computes a compact **windowed drift score** over the model’s most informative static features.

- **Feature subspace**: keep the **strongest 64 dimensions** ($d=64$) selected by the trained model (from the 2304-d PE feature vector).
- **Two windows**: split recent samples into two equal blocks:
  - **PrevWindow**: older half
  - **CurrWindow**: newest half

We flag drift if **either** a normalized mean/variance shift is too large **or** the correlation structure changes too much:

- **Mean/variance shift (normalized mean change)**:
  - For each feature $j$, compute $\mu^{prev}_j, \sigma^{prev}_j$ on PrevWindow and $\mu^{curr}_j$ on CurrWindow.
  - Compute per-feature normalized shift:
    $$
    \Delta_j = \frac{|\mu^{curr}_j - \mu^{prev}_j|}{\sigma^{prev}_j + \epsilon}
    $$
  - Aggregate:
    $$
    \mathrm{mean\_shift} = \frac{1}{d}\sum_{j=1}^{d}\Delta_j
    $$

- **Correlation shift (relationship change)**:
  - Compute Pearson correlation matrices $C^{prev}$ and $C^{curr}$ over the same $d$ features (rows = samples, columns = features).
  - Aggregate:
    $$
    \Delta_{corr} = \mathrm{mean}\left(\left|C^{curr} - C^{prev}\right|\right)
    $$

**Drift flag (high-level):**

```text
drift = (mean_shift too big) OR (corr_shift too big) OR (ADWIN alert)
```

## LLM usage (Ollama): what it does and does not do

Ollama is a **local semantic sidecar**, not the malware classifier and not a safety gate.

- **Used for**:
  - source strategy assistance,
  - structured filtering of unstructured CTI text into SHA256 verdicts,
  - PE parse-error triage assistance,
  - drift explanation narratives based on drift statistics and anomalous static features.
- **Not used for**:
  - classifying binaries as malware/benign,
  - bypassing deterministic validation gates.
- **Fallbacks**: all LLM outputs are best-effort; deterministic routing and validation keep the agent operational when Ollama is unavailable.

## Configuration

### 1) Secrets (`.env`)

Create `.env` from the example:

```powershell
copy .env.example .env
```

Required:

```env
MALWAREBAZAAR_AUTH_KEY=your-auth-key
```

Common optional:

```env
AMD_OLLAMA_BASE_URL=http://localhost:11434
AMD_OLLAMA_MODEL=llama3.1:8b
OTX_API_KEY=...
GITHUB_TOKEN=...
MALSHARE_API_KEY=...
```

### 2) Non-secret tuning (`src/config/`)

- Most tuning lives in [`src/config/`](src/config/) (feature flags in `core.py`, ML settings in `ml_settings.py`, provider settings in `providers.py`).
- You can disable Ollama entirely via `OLLAMA_ENABLED = False` in [`src/config/core.py`](src/config/core.py).

## Outputs and evaluation artifacts

After running for a while (especially in `--daemon`), you will see:

- `data/evaluation_log.jsonl`: periodic TESSERACT-style chronological metrics.
- `data/drift_log.jsonl`: drift-triggered events with pre/post metrics (+ optional drift explanation excerpt).
- `data/model_update_log.jsonl`: strict temporal holdout before/after comparisons for model updates.
- `data/figures/`: plots generated by evaluation runs (e.g., temporal performance decay).

## Thank you
