# AMD-Agent: Autonomous Continual Malware Detection

AMD-Agent is a LangGraph-based malware analysis pipeline for collecting Windows PE samples, extracting static features, detecting concept drift, explaining suspicious drift with Ollama and static PE features, and retraining a LightGBM classifier with MADAR replay.

The project is designed for isolated execution in Docker or a malware-analysis VM. Do not run downloaded binaries.

## Current Architecture

```text
START
  -> SourceSelector (bootstrap vs steady strategies)
      -> benign or bootstrap malware: SourceDiscovery
      -> steady malware: SourceDiscovery (MalwareBazaar + MalShare + fallback top-up)
  -> BinaryFetch
  -> DataValidation
  -> FeatureExtraction
  -> DriftMonitor
      -> no drift: ClassifierInference -> Evaluation -> END
      -> drift: ExplainDriftContext -> ModelRetrain -> Evaluation -> END
```

### Main components

- `SourceSelector`: asks Ollama to choose source strategy when available, with deterministic fallback based on malware/benign balance in SQLite.
- `SourceDiscovery`: discovers samples from one or more registered providers.
- `BinaryFetch`: downloads through each candidate's own provider, not a global provider.
- `DataValidation`: checks MZ header, validates `PE\0\0` at `e_lfanew`, verifies filename SHA256, de-duplicates, skips known corrupted hashes, and syncs SQLite status.
- `FeatureExtraction`: extracts a deterministic 2304-dimensional EMBER-like static vector: PE headers/directories, Authenticode metadata, warnings, byte and byte-entropy histograms, string distributions, hashed imports/exports/sections, and lightweight instruction features. Parse failures are triaged and marked `corrupted`.
- `DriftMonitor`: uses River ADWIN over section entropy plus rolling multivariate shift checks over selected model features.
- `ClassifierInference`: scores samples with an XGBoost-ranked, Optuna-tuned LightGBM pipeline and FPR-aware thresholding (target FPR scales with trainable benign volume in SQLite: 5% below 1k, 1% from 1k–5k, 0.1% at 5k+; see `get_dynamic_target_fpr()` in `src/config.py`).
- `ExplainDriftContext`: asks Ollama to summarize drift statistics and anomalous static PE features into a semantic drift report (deterministic fallback when Ollama is unavailable).
- `ModelRetrain`: retrains with MADAR replay buffer. Single-class retrain batches are skipped safely.
- `Evaluation` (LangGraph node): runs TESSERACT chronological eval on a configurable cadence, appends `evaluation_log.jsonl`, plots decay; on retrain/drift cycles it always runs and writes `drift_log.jsonl` with pre/post metrics.
- `ModelUpdateComparison`: after each successful cold-start or retrain update, compares the previous production model against the updated model on the same temporal holdout and appends `model_update_log.jsonl`.

The initial LightGBM model is not considered ready until SQLite contains at
least 100 active malware samples and 100 active benign samples with extracted
features. Pending hashes and corrupted rows do not count toward this threshold.
Model bundles are also tied to `FEATURE_SET_VERSION`; older 17-feature bundles
are treated as stale and retrained.

## Data Sources

### Malware

- MalwareBazaar API:
  - PE file-type metadata discovery (`exe`, `dll`, `sys`, `scr`) with recent-sample fallback,
  - SHA256-based sample download,
  - password-protected ZIP extraction using password `infected`.

- MalShare API (optional; set `MALSHARE_ENABLED = True` in `src/config.py`):
  - `PE32` hash listing and `getfile` download,
  - active malware collection alongside MalwareBazaar during bootstrap and steady volume fill,
  - fallback when MalwareBazaar circuit/quota blocks (`MB_FALLBACK_MALSHARE = True` in `config.py`).

- AlienVault OTX pulse CTI (`otx_pulse_cti`):
  - live pulse retrieval through `src/tools/clients/otx_api_client.py`,
  - SHA256 indicator extraction from OTX pulse indicators,
  - pulse names, descriptions, references, tags, and indicator text combined into `raw_text`,
  - structured semantic hash filtering through Ollama when available.

OTX and curated CTI feeds use a Hybrid Strict policy: CTI text is used only as evidence for hashes. Arbitrary CTI URLs are not used for binary download.

### Benign

- Sysinternals live directory.
- GitHub release `.exe` and `.zip` assets from curated benign repositories.
- Benign-NET (`benign_net` provider): shallow git clone under `data/repos/benign-net` (capped per run via `BENIGN_NET_MAX_DISCOVER`).
- Optional local benign corpus under `data/benign`.

### PE source registry (optional)

- `pe_sources` SQLite table stores discovered dataset/API/repo metadata (`PESourceStore`).
- Enable autonomous URL discovery with `PE_SOURCE_DISCOVERY_ENABLED = True` in `config.py` (node `pe_source_discovery` runs before steady malware ingest when active sources are below `MIN_PE_SOURCES` or after concept drift).
- OOP HTTP clients live under `src/tools/clients/` (`MalwareBazaarClient`, `MalShareClient`, `ThreatFoxClient`).

## Safety And Persistence

- Docker runs on isolated `malware_net`.
- `docker/entrypoint.sh` blocks egress to private/local subnets with `iptables`.
- `docker-compose.yml` grants `NET_ADMIN`, required for those `iptables` rules.
- Docker allows the configured Ollama endpoint before private subnet blocking.
- SQLite uses WAL mode to reduce lock errors during long-running collection.
- LangGraph uses `MemorySaver` checkpointer with default thread id `amd-agent-default`.
- Downloaded samples are stored under sandbox paths and are never executed.
- Benign collection fans out across selected providers (`sysinternals`, `github`, `benign_net`) and records source URLs/paths to avoid retrying the same assets.

## SQLite Sample Status

`samples` rows include:

| Column | Meaning |
|---|---|
| `sha256` | sample hash |
| `file_path` | sandbox path; empty string for pending queue rows |
| `acquired_at` | acquisition timestamp |
| `features_json` | extracted static PE features |
| `feature_version` | feature schema version, e.g. `ember_static_v1` |
| `feature_dim` | feature vector width, currently `2304` |
| `label` | `1` malware, `0` benign |
| `prediction` | LightGBM malicious probability |
| `anomaly_score` | reserved anomaly score |
| `status` | `pending`, `active`, or `corrupted` |
| `reject_reason` | raw rejection/parse reason |
| `rejected_at` | rejection timestamp |
| `source_provider` | originating provider when known |
| `source_url` | originating URL when known; used to avoid re-fetching URL-only benign assets |
| `ingested_at` | local ingestion timestamp used for TESSERACT chronological order |
| `source_first_seen` | provider-side first-seen timestamp, when available |

OTX and curated CTI fallback can validate hashes and load pending malware rows where `file_path=''` and `status` is `pending` or `active`. Rows marked `corrupted` are not retried.

`provider_runs` stores recent provider yield metrics and drives cooldowns.
`candidates` stores provider refs/status/attempts without storing PE bytes.

## Requirements

- Python 3.12.
- Docker Desktop for container execution.
- MalwareBazaar API key.
- AlienVault OTX API key when `otx_pulse_cti` is enabled.
- Ollama running locally for source choice, structured CTI parsing, and drift reports.

All Python dependencies live in `requirements.txt`. Local installs and Docker both use `pip install -r requirements.txt`. Any change to that file invalidates the Docker dependency wheel layer on rebuild.

Installed dependencies include:

- `langgraph`, `pydantic`
- `langchain-ollama`, `langchain-core`
- `httpx`, `beautifulsoup4`, `OTXv2`
- `pefile`, `pyzipper`
- `river`, `lightgbm`, `scikit-learn`
- `xgboost`, `optuna`, `capstone`
- `numpy`, `pandas`, `joblib`, `matplotlib`
- `pytest`, `pytest-httpx`
- `feedparser`, `regex`

## Configuration

Create local environment file:

```powershell
copy .env.example .env
```

Required:

```env
MALWAREBAZAAR_AUTH_KEY=your-auth-key
```

Common Ollama setup (in `.env`):

```env
AMD_OLLAMA_BASE_URL=http://localhost:11434
AMD_OLLAMA_MODEL=gemma4:latest
```

Disable Ollama entirely by setting `OLLAMA_ENABLED = False` in [`src/config.py`](src/config.py).

In Docker, compose also reads `AMD_OLLAMA_BASE_URL`. If the variable is not set,
compose defaults it to:

```env
AMD_OLLAMA_BASE_URL=http://ollama-host:11434
```

If Docker runs inside a Windows VM and Ollama runs on the physical host, set the
same variable to an IP address that the VM can reach, for example:

```env
AMD_OLLAMA_BASE_URL=http://192.168.56.1:11434
```

If you want the README default model instead:

```powershell
ollama pull llama3.1:8b
```

Optional secrets and endpoints (see [`.env.example`](.env.example)):

| Variable | Purpose |
|---|---|
| `GITHUB_TOKEN` | GitHub API rate limits for benign release discovery |
| `MALSHARE_API_KEY` | MalShare malware API (enable with `MALSHARE_ENABLED` in `config.py`) |
| `OTX_API_KEY` | AlienVault OTX pulse CTI |
| `AMD_OLLAMA_BASE_URL` | Ollama HTTP endpoint |
| `AMD_OLLAMA_MODEL` | Ollama model tag (e.g. `llama3.1:8b`) |

**All other tuning** (scheduler interval, bootstrap limits, drift/ADWIN, MalwareBazaar throttles, provider cooldowns, feature flags such as `ALLOW_LOCAL_BENIGN`, `PE_SOURCE_DISCOVERY_ENABLED`, `FORCED_BENIGN_PROVIDER`, Ollama timeouts, etc.) lives in [`src/config.py`](src/config.py). Edit constants there instead of `.env`. Settings are grouped under `# --- ... ---` section headlines (paths, ML, collection, external APIs).

### Logging

- **`VERBOSE`** in [`src/config.py`](src/config.py): `False` (default) prints phase-prefixed summaries on the console; `True` also prints per-item detail (skips, cache hits, API traces).
- **Log file**: `data/logs/amd-agent.log` (local) or `/data/logs/amd-agent.log` (container). The file always retains full detail for post-mortem review; rotation is controlled by `LOG_MAX_BYTES` / `LOG_BACKUP_COUNT`.
- **TTY spinners**: when `VERBOSE=False` and stderr is an interactive terminal, long steps show Rich status spinners; Docker/non-TTY runs use plain `[PHASE]` lines only.
- Setup lives in [`src/log.py`](src/log.py); call `configure_logging()` once at process entry (`python -m src.graph`, preflight script).
- **Ollama comms**: [`src/llm/ollama_trace.py`](src/llm/ollama_trace.py) logs each call with `[LLM]` lifecycle lines on the console (`sending`, `waiting`, `response OK` / `failed`). Full prompts and responses are always written to `amd-agent.log`. Set `OLLAMA_LOG_DETAIL = True` in `src/config.py` for short console previews of payloads (`OLLAMA_LOG_CONSOLE_PREVIEW` chars).

Legacy search keys in an existing `.env` are ignored after this change; prune them when convenient.

## Docker Run

Start Docker Desktop first.

Build:

```powershell
docker compose build
```

Run once:

```powershell
docker compose run --rm amd-agent python -m src.graph --once
```

Preflight diagnostics (local or before deploy):

```powershell
$env:PYTHONPATH="."
python scripts/preflight_check.py
```

Production stack (`amd-agent` runs preflight, conditional bootstrap, then daemon):

```powershell
docker compose up --force-recreate
```

The default `amd-agent` command (`docker/amd-agent-run.sh`) skips bootstrap when
trainable counts and `model.pkl` are already ready, then stays in `--daemon`
(scheduler interval default 1800s; tune `SCHED_INTERVAL_SECONDS` in `src/config.py`).

One-off graph pass:

```powershell
docker compose run --rm amd-agent python -m src.graph --once
```

Manual bootstrap only (no daemon):

```powershell
docker compose run --rm amd-agent python -m src.graph --bootstrap
```

Manual daemon only:

```powershell
docker compose run --rm amd-agent python -m src.graph --daemon
```

Docker persists DB, models, logs, and figures under `./data`.

## Local Run

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Set Python path:

```powershell
$env:PYTHONPATH="."
```

Run once:

```powershell
python -m src.graph --once
```

Run daemon:

```powershell
python -m src.graph --daemon
```

## Malware CTI Fallback

Steady malware collection goes directly through active source discovery:
MalwareBazaar plus MalShare when enabled. If those sources under-fill the batch,
the configured fallback chain is `malshare`, `threatfox`, then `otx_pulse_cti`.

`otx_pulse_cti` retrieves recent AlienVault OTX pulses, extracts structured
SHA256 indicators, sends the pulse `raw_text` to Ollama for structured semantic
filtering, and validates accepted hashes with MalwareBazaar before queuing or
downloading samples. The local Ollama integration is a parser/verdict layer here,
not a source-discovery or search agent.

| Capability | Implementation |
|---|---|
| Curated CTI feeds | `src/intel/seed_sources.py` for in-process polling |
| Live OTX pulse provider | `src/sources/otx_pulse_cti.py` + `src/tools/clients/otx_api_client.py` |
| Structured hash verdicts | `src/llm/client.py`: `SemanticHashVerdict`, `semantic_filter_hashes` |
| Confidence gating | `SEMANTIC_MIN_CONFIDENCE`, `SEMANTIC_REQUIRE_TECHNICAL_REPORT` in `src/config.py` |
| Upstream validation | SHA256 + MalwareBazaar `is_pe_hash` before pending insert |
| Multi-provider download | `src/tools/pe_download.py`: MB (retry) -> allowlisted URL |
| LangGraph tools | `poll_intel_feeds`, `validate_and_queue_candidates` |

Run the agent:

```powershell
docker compose up --force-recreate
```

| Setting | Purpose |
|---|---|
| `OTX_API_KEY` | Required in `.env` for live OTX pulse ingestion |
| `OTX_ENABLED` | Enable/disable OTX provider in `src/config.py` |
| `OTX_PULSE_DAYS` / `OTX_PULSE_LIMIT` | OTX pulse lookback and API result cap in `src/config.py` |
| `CTI_SEED_SOURCES_ENABLED` | Keep curated CTI feeds enabled in the native source registry (`src/config.py`) |

Pending row contract:

| Column | Value |
|---|---|
| `sha256` | 64-char SHA256 or allowlisted URL key |
| `file_path` | empty until fetched |
| `label` | `1` |
| `status` | `pending` |

## Evaluation

The `evaluation` LangGraph node (`src/nodes/evaluation_node.py`) sits at the end of every graph pass, but TESSERACT only runs every `EVAL_EVERY_RUNS` steady-state passes. It is skipped during bootstrap by default and forced after every retrain attempt, including skipped retrains. TESSERACT logic lives in `src/evaluation/tesseract.py`.

It uses:

- chronological train/validation/test splits with a temporary temporal model,
- accuracy, precision, recall, FPR,
- dynamic threshold targeting adaptive FPR (`resolve_target_fpr()`; production ceiling `TARGET_FPR = 0.001` at 5k+ benign),
- AUT (`Area Under Time`) over historical accuracy,
- performance plot at `FIGURES_DIR/performance_decay.png`.

If the temporal validation or test split contains only one class, TESSERACT is
skipped instead of emitting misleading precision/recall. Cold-start training
uses a stratified split so the initial 100/100 bootstrap model is stable even
when provider batches arrive in an uneven chronological order; temporal
TESSERACT remains the research/evaluation view.

New samples sort temporal evaluation by `ingested_at`; provider timestamps such
as MalwareBazaar `first_seen` are preserved as `source_first_seen` but do not
control TESSERACT chronology. While train/validation/test splits are
single-class, steady collection switches to mixed malware/benign batches.

Local default figure path:

```text
report/figures/performance_decay.png
```

Docker figure path:

```text
/data/figures/performance_decay.png
```

The LaTeX report references `figures/performance_decay.png` and will not fail if the plot is not generated yet.

Report artifacts (Docker paths; local dev uses `data/`):

| File | Purpose |
|------|---------|
| `/data/evaluation_log.jsonl` | Per-run TESSERACT metrics (accuracy, FPR, AUT) |
| `/data/evaluation_state.json` | Persistent counter for periodic evaluation cadence |
| `/data/drift_log.jsonl` | Concept drift events with pre/post metrics and semantic report excerpt |
| `/data/model_update_log.jsonl` | Per-model-update before/after metrics: accuracy, precision, recall, FPR |
| `/data/figures/performance_decay.png` | Accuracy/FPR over evaluation runs |

For LaTeX builds, copy or symlink the decay plot into `report/figures/performance_decay.png` after a long daemon session.

### Submission checklist

- Keep `ALLOW_LOCAL_BENIGN = False` in `src/config.py` (default).
- Keep `data/benign/` empty for experiments (no pre-seeded benign PEs).
- Run `python scripts/preflight_check.py` and resolve warnings about local benign.
- Generate report evidence: bootstrap if needed, then `--daemon` until `drift_log.jsonl` has several drift/retrain cycles.

## Tests

Layout mirrors `src/` packages (`tests/test_workflow/`, `tests/test_collection/`, …). Shared fixtures live in `tests/conftest.py`.

Run the full suite (always pass the `tests/` directory — no `pytest.ini`):

```powershell
python -m pytest tests/ -q
docker compose run --rm amd-agent pytest tests/ -q
```

Run one package:

```powershell
python -m pytest tests/test_ml/ -q
docker compose run --rm amd-agent pytest tests/test_workflow/ -q
```

Fast static check:

```powershell
python -m compileall -q src tests
```

Docker config check:

```powershell
docker compose config
```

## Production verification (steady state)

Before leaving the stack running continuously:

1. `python scripts/preflight_check.py` — phase, per-class trainable counts, bundle ready, pending depth.
2. `docker compose up` — logs show `bootstrap skipped` or bootstrap complete, then `Scheduler started`.
3. Steady malware passes hit active MalwareBazaar/MalShare discovery directly, with fallback top-up if needed.
4. After new samples extract features, ADWIN updates use `ADWIN_DELTA` in `config.py` (tune if single-file retrains are too frequent).

## Known Runtime Checklist

Before a smooth run:

- `.env` exists.
- `MALWAREBAZAAR_AUTH_KEY` is set.
- Docker Desktop is running if using Docker.
- Ollama is reachable:

```powershell
curl.exe http://localhost:11434/api/tags
```

- `AMD_OLLAMA_MODEL` matches an installed Ollama model.
- `data/benign` contains enough benign PE files, or live benign providers are reachable.
- `python -m pytest tests/ -q` works after dependencies are installed.

## Troubleshooting

### `Missing MALWAREBAZAAR_AUTH_KEY`

Create `.env` and set the key:

```powershell
copy .env.example .env
```

### Ollama model not found

Either pull the configured model:

```powershell
ollama pull llama3.1:8b
```

Or set `.env` to an installed model:

```env
AMD_OLLAMA_MODEL=gemma4:latest
```

### Docker cannot connect

Start Docker Desktop, then rerun:

```powershell
docker compose build
```

### SQLite locked

WAL mode is enabled. If locks persist, ensure no long-lived manual SQLite shell holds a transaction.

## Security Notes

- Do not execute samples.
- Use a VM or Docker.
- Treat `data/sandbox` as malicious.
- Keep MalwareBazaar and GitHub tokens private.
- Respect source rate limits; MalwareBazaar, ThreatFox, MalShare, and OTX clients include throttling/circuit handling.
