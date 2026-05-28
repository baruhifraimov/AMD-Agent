# AMD-Agent: Autonomous Malware Detection Agent

AMD-Agent is an autonomous, LLM-assisted continual-learning system for **Windows PE malware detection**. It continuously collects malware and benign samples from live sources, validates and featurizes them using safe static analysis, monitors **concept drift**, and updates a **LightGBM** classifier using **replay-based retraining**. Each model update is evaluated with a **strict temporal holdout** to enable reliable before/after comparisons.

**Safety:** AMD-Agent ingests live, weaponized binaries. **Do not execute downloaded samples.** Run only in Docker or an isolated malware-analysis VM.

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

## Quickstart (Docker)

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

## Outputs and evaluation artifacts

After running for a while (especially in `--daemon`), you will see:

- `data/evaluation_log.jsonl`: periodic TESSERACT-style chronological metrics.
- `data/drift_log.jsonl`: drift-triggered events with pre/post metrics (+ optional drift explanation excerpt).
- `data/model_update_log.jsonl`: strict temporal holdout before/after comparisons for model updates.
- `data/figures/`: plots generated by evaluation runs (e.g., temporal performance decay).

## Thank you
