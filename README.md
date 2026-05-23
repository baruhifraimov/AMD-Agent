# AMD-Agent: Autonomous Continual Malware Detection

AMD-Agent is a LangGraph-based malware analysis pipeline for collecting Windows PE samples, extracting static features, detecting concept drift, explaining suspicious drift with capa + Ollama, and retraining a LightGBM classifier with MADAR replay.

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
- `ClassifierInference`: scores samples with an XGBoost-ranked, Optuna-tuned LightGBM pipeline and FPR-aware thresholding.
- `ExplainDriftContext`: runs `capa -j -r <rules_dir>` and asks Ollama to produce a semantic drift report.
- `ModelRetrain`: retrains with MADAR replay buffer. Single-class retrain batches are skipped safely.
- `Evaluation` (LangGraph node): runs TESSERACT chronological eval on a configurable cadence, appends `evaluation_log.jsonl`, plots decay; on retrain/drift cycles it always runs and writes `drift_log.jsonl` with pre/post metrics.

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

- MalShare API (optional, `AMD_MALSHARE_ENABLED=1`):
  - `PE32` hash listing and `getfile` download,
  - active malware collection alongside MalwareBazaar during bootstrap and steady volume fill,
  - fallback when MalwareBazaar circuit/quota blocks (`AMD_MB_FALLBACK_MALSHARE=1`).

- Dynamic CTI discovery:
  - configurable `ddgs` backends and optional Brave Search API,
  - public CTI page fetching with strict byte truncation,
  - SHA256 extraction with surrounding evidence,
  - semantic hash filtering through Ollama when available.

Dynamic CTI uses a Hybrid Strict policy: CTI pages are used only as evidence for hashes. Arbitrary CTI URLs are not used for binary download.

### Benign

- Sysinternals live directory.
- GitHub release `.exe` and `.zip` assets from curated benign repositories.
- Benign-NET (`benign_net` provider): shallow git clone under `data/repos/benign-net` (capped per run via `BENIGN_NET_MAX_DISCOVER`).
- Optional local benign corpus under `data/benign`.

### PE source registry (optional)

- `pe_sources` SQLite table stores discovered dataset/API/repo metadata (`PESourceStore`).
- Enable autonomous URL discovery with `AMD_PE_SOURCE_DISCOVERY=1` (node `pe_source_discovery` runs before steady malware ingest when active sources are below `MIN_PE_SOURCES` or after concept drift).
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

Dynamic CTI fallback can validate hashes and load pending malware rows where `file_path=''` and `status` is `pending` or `active`. Rows marked `corrupted` are not retried.

`provider_runs` stores recent provider yield metrics and drives cooldowns.
`candidates` stores provider refs/status/attempts without storing PE bytes.

## Requirements

- Python 3.12.
- Docker Desktop for container execution.
- MalwareBazaar API key.
- Ollama running locally for LLM decisions/reports.
- capa rules directory:
  - Docker build clones official `capa-rules` into `/opt/capa-rules`.
  - Local runs need `AMD_CAPA_RULES_DIR` pointing to a valid rules directory.

Python dependencies are split for Docker cache stability:

- `requirements.base.txt`: heavy/stable project dependencies.
- `requirements.txt`: includes the base file for local installs and is the place to add new project dependencies.

Docker installs `requirements.base.txt` in a stable cached layer first. New direct dependencies added to `requirements.txt` are installed in a later small layer, so the base dependency set is not reinstalled.

Installed dependencies include:

- `langgraph`, `pydantic`
- `langchain-ollama`, `langchain-core`
- `httpx`, `beautifulsoup4`, `ddgs`
- `pefile`, `pyzipper`, `flare-capa`
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

Common Ollama setup:

```env
AMD_OLLAMA_ENABLED=1
AMD_OLLAMA_BASE_URL=http://localhost:11434
AMD_OLLAMA_MODEL=gemma4:latest
AMD_OLLAMA_TIMEOUT=8
```

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

Other useful variables:

| Variable | Purpose |
|---|---|
| `GITHUB_TOKEN` | optional GitHub token for release API rate limits |
| `MALWAREBAZAAR_AUTH_KEY` | abuse.ch key for MalwareBazaar, ThreatFox, and Twitter/X CTI (social refs via ThreatFox API) |
| `AMD_BENIGN_PROVIDER` | force benign provider: `sysinternals`, `github`, or `benign_net` |
| `MALSHARE_API_KEY` | MalShare API key (optional malware source) |
| `AMD_MALSHARE_ENABLED` | enable MalShare provider and client (`0`/`1`) |
| `AMD_MB_FALLBACK_MALSHARE` | try MalShare when MalwareBazaar download fails (`0`/`1`) |
| `BENIGN_NET_REPO_URL` | git URL for Benign-NET clone (default bormaa/Benign-NET) |
| `BENIGN_NET_MAX_DISCOVER` | max `.exe` paths discovered per run from Benign-NET (default `20`) |
| `AMD_PE_SOURCE_DISCOVERY` | enable `pe_source_discovery` node and URL registry updates (`0`/`1`) |
| `AMD_PE_DISCOVERY_MAX_URLS_PER_RUN` | max URLs fetched/classified per discovery pass (default `8`) |
| `MIN_PE_SOURCES` | run PE discovery when active `pe_sources` count is below this (default `3`) |
| `AMD_ALLOW_LOCAL_BENIGN` | ingest `data/benign/*` as label `0` |
| `AMD_CTI_SEED_SOURCES_ENABLED` | seed known CTI feeds into `intel_sources` before polling (default `1`) |
| `AMD_INTEL_MIN_POLL_INTERVAL` | minimum seconds between polls per high-yield source |
| `AMD_INTEL_MAX_POLL_INTERVAL` | maximum seconds between polls per low-yield source |
| `AMD_PROVIDER_COOLDOWN_ZERO_RUNS` | zero-yield provider runs before cooldown (default `3`) |
| `AMD_PROVIDER_COOLDOWN_SECONDS` | provider cooldown duration in seconds (default `43200`) |
| `AMD_PROVIDER_COOLDOWN_MIN_ATTEMPTS` | minimum requested/attempted candidates before cooldown applies (default `5`) |
| `AMD_STEADY_BENIGN_EVERY_N` | benign refresh cadence once temporal splits are healthy (default `4`) |
| `AMD_TESSERACT_MIXED_UNTIL_HEALTHY` | collect mixed malware/benign steady batches until temporal splits contain both labels (default `1`) |
| `AMD_OLLAMA_SOURCE_SELECTION` | bind intel `@tool`s for Ollama source selection |
| `AMD_CTI_DOWNLOAD_ALLOWLIST` | comma-separated hosts allowed for direct PE URL fallback |
| `AMD_PE_FETCH_LIMIT` | max candidates returned per discovery pass (default `10`) |
| `AMD_MALWARE_FALLBACK_PROVIDERS` | malware fallback chain after active MalwareBazaar/MalShare discovery, e.g. `malshare,threatfox,dynamic_cti` |
| `AMD_FALLBACK_PE_CHECK_MULT` | max PE-validation checks per requested fallback candidate multiplier (default `1`) |
| `AMD_PE_DOWNLOAD_MAX_BYTES` | max bytes for allowlisted direct downloads |
| `AMD_CAPA_RULES_DIR` | capa rules directory passed with `-r` |
| `AMD_REPORT_LANGUAGE` | language for Ollama drift report |
| `AMD_CTI_SEARCH_LIMIT` | max search results per CTI query |
| `AMD_CTI_SEARCH_BACKENDS` | comma-separated `ddgs` text backends, for example `duckduckgo,brave` |
| `AMD_BRAVE_SEARCH_API_KEY` | optional Brave Search API key for CTI page discovery |
| `AMD_CTI_PAGE_LIMIT` | max CTI pages per discovery run |
| `AMD_CTI_PAGE_MAX_BYTES` | max bytes read from each CTI page |
| `AMD_CTI_REQUEST_TIMEOUT` | CTI HTTP timeout |
| `AMD_BOOTSTRAP_MAX_RUNS` | max bootstrap graph passes before giving up (default `60`) |
| `AMD_BOOTSTRAP_INTERVAL` | seconds between bootstrap passes (default `10`) |
| `AMD_ADWIN_DELTA` | River ADWIN confidence bound (default `0.002`; higher = less sensitive) |
| `AMD_DRIFT_WINDOW_DAYS` | target temporal window for multivariate drift tracking (default `60`) |
| `AMD_DRIFT_MIN_WINDOW_SAMPLES` | minimum samples per rolling drift window (default `50`) |
| `AMD_REPLAY_FRACTION` | historical data fraction used for MADAR replay, capped by `REPLAY_BUDGET` (default `0.3`) |
| `AMD_FEATURE_SELECTION_K` | number of XGBoost-ranked features retained for LightGBM (default `384`) |
| `AMD_OPTUNA_TRIALS` | LightGBM tuning trials (default `25`; set `0` to disable) |
| `AMD_OPTUNA_TIMEOUT` | Optuna tuning timeout in seconds (default `300`) |
| `AMD_EVAL_EVERY_RUNS` | run periodic TESSERACT eval every N steady-state graph passes (default `10`) |
| `AMD_EVAL_SKIP_BOOTSTRAP` | skip periodic TESSERACT eval during bootstrap (default `1`) |
| `AMD_MB_MIN_REQUEST_INTERVAL` | minimum seconds between MalwareBazaar POST requests (default `1.5`) |
| `AMD_MB_USER_AGENT` | custom User-Agent for MB API (default identifies AMD-Agent research use) |
| `AMD_MB_USER_AGENT_CONTACT` | optional contact string appended to User-Agent |
| `AMD_MB_INFO_CACHE_TTL_DAYS` | SQLite cache TTL for `get_info` / PE verdict lookups (default `30`) |
| `AMD_MB_DAILY_DOWNLOAD_LIMIT` | max `get_file` downloads per UTC day per IP (default `1900`, under abuse.ch 2000 cap) |
| `AMD_MB_MAX_INFO_CALLS_PER_RUN` | max `get_info` calls per graph run (`0` = unlimited) |
| `AMD_MB_CIRCUIT_FAILURE_THRESHOLD` | consecutive MB 5xx/transport failures before circuit opens (default `3`) |
| `AMD_MB_CIRCUIT_OPEN_SECONDS` | seconds to skip MB API calls while circuit is open after 5xx (default `120`) |
| `AMD_MB_CIRCUIT_OPEN_SECONDS_429` | seconds to skip MB API after HTTP 429 backoff exhausted (default `3600`) |
| `AMD_CTI_HOST_BLOCK_SECONDS_403` | block CTI host after HTTP 403 (default `900`) |
| `AMD_CTI_HOST_BLOCK_SECONDS_429` | block CTI host after HTTP 429 (default `3600`) |
| `AMD_CTI_HOST_BLOCK_SECONDS_TRANSPORT` | block CTI host after connection errors (default `300`) |

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
(scheduler interval default 1800s; tune `AMD_SCHED_INTERVAL` in `.env`).

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

Local capa setup example:

```powershell
git clone https://github.com/mandiant/capa-rules.git C:\capa-rules
$env:AMD_CAPA_RULES_DIR="C:\capa-rules"
```

## Malware CTI Fallback

Steady malware collection goes directly through active source discovery:
MalwareBazaar plus MalShare when enabled. If those sources under-fill the batch,
the configured fallback chain can include `threatfox` and `dynamic_cti`.

`dynamic_cti` uses the native collector to seed high-signal public CTI feeds
(DFIR Report, Cisco Talos, Google Threat Intelligence, CISA advisories, Unit42,
Securelist, and Malwarebytes) before falling back to web-search source discovery.
Search results from academic/paywalled hosts are ignored because they rarely
produce actionable PE SHA256 indicators.

| Capability | Implementation |
|---|---|
| Curated CTI feeds | `src/intel/seed_sources.py` for in-process polling |
| Dynamic source discovery | Web search + LLM → `intel_sources` (native `feedparser` polls) |
| Upstream validation | SHA256 + MalwareBazaar `is_pe_hash` before pending insert |
| Multi-provider download | `src/tools/pe_download.py`: MB (retry) → allowlisted URL |
| LangGraph tools | `discover_intel_sources`, `poll_intel_feeds`, `validate_and_queue_candidates` |

Run the agent:

```powershell
docker compose up --force-recreate
```

| Env var | Purpose |
|---|---|
| `AMD_CTI_SEED_SOURCES_ENABLED` | Keep curated CTI feeds enabled in the native source registry |

Pending row contract:

| Column | Value |
|---|---|
| `sha256` | 64-char SHA256 or allowlisted URL key |
| `file_path` | empty until fetched |
| `label` | `1` |
| `status` | `pending` |

## Evaluation

The `evaluation` LangGraph node (`src/nodes/evaluation_node.py`) sits at the end of every graph pass, but TESSERACT only runs every `AMD_EVAL_EVERY_RUNS` steady-state passes. It is skipped during bootstrap by default and forced after every retrain attempt, including skipped retrains. TESSERACT logic lives in `src/evaluation/tesseract.py`.

It uses:

- chronological train/validation/test splits with a temporary temporal model,
- accuracy, precision, recall, FPR,
- dynamic threshold targeting `TARGET_FPR = 0.001`,
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
| `/data/drift_log.jsonl` | Concept drift events with pre/post metrics and capa excerpt |
| `/data/figures/performance_decay.png` | Accuracy/FPR over evaluation runs |

For LaTeX builds, copy or symlink the decay plot into `report/figures/performance_decay.png` after a long daemon session.

### Submission checklist

- Set `AMD_ALLOW_LOCAL_BENIGN=0` in `.env` (default in `.env.example`).
- Keep `data/benign/` empty for experiments (no pre-seeded benign PEs).
- Run `python scripts/preflight_check.py` and resolve warnings about local benign.
- Generate report evidence: bootstrap if needed, then `--daemon` until `drift_log.jsonl` has several drift/retrain cycles.

## Tests

Run:

```powershell
python -m pytest -q
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
4. After new samples extract features, ADWIN updates use `AMD_ADWIN_DELTA` (tune if single-file retrains are too frequent).

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
- `AMD_CAPA_RULES_DIR` points to a real capa rules directory for local runs.
- `data/benign` contains enough benign PE files, or live benign providers are reachable.
- `python -m pytest -q` works after dependencies are installed.

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

### capa rules missing locally

Clone rules and set env:

```powershell
git clone https://github.com/mandiant/capa-rules.git C:\capa-rules
$env:AMD_CAPA_RULES_DIR="C:\capa-rules"
```

### SQLite locked

WAL mode is enabled. If locks persist, ensure no long-lived manual SQLite shell holds a transaction.

## Security Notes

- Do not execute samples.
- Use a VM or Docker.
- Treat `data/sandbox` as malicious.
- Keep MalwareBazaar and GitHub tokens private.
- Respect source rate limits; Dynamic CTI includes query jitter and page-size truncation.
