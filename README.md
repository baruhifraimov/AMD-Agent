# AMD-Agent: Autonomous Continual Malware Detection

## Project Purpose

AMD-Agent is a cybersecurity ML pipeline designed to:

- continuously collect Windows PE samples from internet sources,
- classify samples as malicious or benign using static analysis features,
- detect concept drift in incoming malware behavior, and
- retrain itself with replay-based continual learning to stay effective over time.

The system is built for safe, repeatable operation in an isolated environment (VM and/or container), with persistent state in SQLite.

## How the Pipeline Works

High-level graph flow:

```
START → SourceSelector ─┬─ (benign) → SourceDiscovery → BinaryFetch
                        └─ (malware) → ThreatQueue ─┬─ queue has hashes → BinaryFetch
                                                    └─ queue empty      → SourceDiscovery
      → DataValidation → FeatureExtraction → DriftMonitor ─┬─ no drift → ClassifierInference → END
                                                           └─ drift    → ActiveLearningExplain → ModelRetrain → END
```

### Node-by-node behavior

1. `SourceSelector`
   - Uses Ollama tool binding when available, with deterministic fallback.
   - Chooses malware vs benign ingestion mode based on dataset balance in SQLite.
   - Helps ensure the model sees enough benign negatives for valid FPR tuning.

2. `ThreatQueue` (malware path only)
   - Pulls pending malware hashes inserted by external ThreatIngestor daemon.
   - If queue has work, pipeline downloads those hashes first.
   - If queue is empty, falls back to live discovery from source APIs.

3. `SourceDiscovery`
   - Discovers candidate PE items from selected provider(s): MalwareBazaar, Dynamic CTI, Sysinternals, GitHub releases.

4. `BinaryFetch`
   - Downloads bytes using provider-specific logic.
   - Computes content SHA256 and stores sample under sandbox path.

5. `DataValidation`
   - Checks PE signature (`MZ`).
   - Handles duplicate semantics:
     - already-downloaded samples are skipped,
     - pending ThreatIngestor rows are updated with file path.

6. `FeatureExtraction`
   - Extracts fixed PE feature vector (15 features) via `pefile`.

7. `DriftMonitor`
   - Uses River ADWIN on entropy stream to flag drift.

8. `ClassifierInference` (no drift)
   - Loads LightGBM model bundle, predicts malicious probabilities, tracks threshold/FPR metrics.

9. `ActiveLearningExplain` + `ModelRetrain` (drift)
   - Runs Mandiant capa with an explicit rules directory and asks Ollama to summarize drift capabilities.
   - Retrains using MADAR-style replay:
     - IsolationForest sampling,
     - 80/20 core/outlier replay split,
     - retrain LightGBM and persist updated model.

## Data Sources and Discovery Tools

### Malware source
- **MalwareBazaar API**
  - `get_recent` for live discovery
  - `get_file` for SHA256-based sample retrieval
  - password-protected ZIP extraction (`infected`)

- **Dynamic CTI discovery**
  - Uses DuckDuckGo search and public CTI page text to discover SHA256 indicators.
  - Hybrid Strict policy: CTI pages provide evidence only; binary downloads still go through registered providers.

### Benign sources
- **Sysinternals live directory**
  - scrapes `.exe` links from Microsoft-hosted pages
- **GitHub Releases API**
  - pulls `.exe` / `.zip` release assets from curated repositories

### External queue source (optional but recommended)
- **ThreatIngestor daemon** (Option A)
  - runs independently in background,
  - inserts pending hashes into SQLite (`file_path=''`, `label=1`),
  - pipeline consumes queue before live malware polling.

## Libraries and Technologies Used

### Core orchestration and state
- `langgraph` — workflow graph and conditional routing
- LangGraph `MemorySaver` checkpointer for in-process state persistence
- `pydantic` — strict state/config models
- `langchain-ollama` — local Ollama tool binding and report generation

### Networking and parsing
- `httpx` — API/HTTP client
- `beautifulsoup4` — benign source HTML parsing
- `pyzipper` / `zipfile` — ZIP extraction

### Malware static analysis and ML
- `pefile` — PE structure and import extraction
- `river` — ADWIN concept drift detection
- `lightgbm` — classifier baseline
- `scikit-learn` — IsolationForest for MADAR replay sampling
- `numpy`, `pandas`, `joblib` — numerical work and persistence

### Storage, evaluation, runtime
- `sqlite3` — persistent sample tracker (`malware_tracker.db`)
- `matplotlib` — temporal performance plots
- `flare-capa` + `capa-rules` — malware capability extraction during drift explanation
- custom scheduler loop (`--daemon`) + YAML/env configuration

### Environment and operations
- Python 3.12
- Docker support (optional)
- VM-first security posture for handling live malware

## Runtime Modes

### Single run
```bash
export PYTHONPATH=.
python -m src.graph --once
```

### Continuous daemon
```bash
export PYTHONPATH=.
export AMD_SCHED_ENABLED=1
export AMD_SCHED_INTERVAL=1800
python -m src.graph --daemon
```

### Daemon with YAML config
```bash
cp scheduler.yaml.example scheduler.yaml
python -m src.graph --daemon --config scheduler.yaml
```

## Key Configuration Variables

| Variable | Description |
|---|---|
| `MALWAREBAZAAR_AUTH_KEY` | Required API key for MalwareBazaar |
| `GITHUB_TOKEN` | Optional token to reduce GitHub API rate limits |
| `AMD_SCHED_ENABLED` | Enable scheduler mode |
| `AMD_SCHED_INTERVAL` | Seconds between scheduled runs |
| `AMD_BENIGN_PROVIDER` | Force benign provider (`sysinternals` or `github`) |
| `AMD_ALLOW_LOCAL_BENIGN` | Optional local benign fallback |
| `AMD_THREAT_QUEUE_ENABLED` | Enable ThreatIngestor pending queue consumption |
| `AMD_OLLAMA_ENABLED` | Enable Ollama decisions/summaries (`0` disables) |
| `AMD_OLLAMA_BASE_URL` | Ollama endpoint |
| `AMD_OLLAMA_MODEL` | Local Ollama model name |
| `AMD_CAPA_RULES_DIR` | capa rules directory passed with `capa -r` |
| `AMD_REPORT_LANGUAGE` | Language for LLM drift report |

## ThreatIngestor Integration (Option A)

Use two processes:

```bash
# Terminal 1: external hash discovery
cp threatingestor_config.yml.example threatingestor_config.yml
threatingestor -c threatingestor_config.yml

# Terminal 2: pipeline processing loop
export PYTHONPATH=.
python -m src.graph --daemon
```

Pending row contract in SQLite:

| Column | Value |
|---|---|
| `sha256` | 64-char hash |
| `file_path` | empty string (`''`) |
| `label` | `1` |
| `acquired_at` | timestamp |
| `status` | `pending` for queued rows; `corrupted` rows are skipped |

## Evaluation

Temporal (TESSERACT-style) evaluation is provided in `src/evaluation/tesseract.py`:

- chronological splits (train/val/test by time),
- metrics: accuracy, precision, recall, FPR,
- AUT (`Area Under Time`) over chronological accuracy,
- evaluation log + `FIGURES_DIR/performance_decay.png`.

## Security Notes

- Do not execute downloaded binaries.
- Run in isolated VM/container only.
- Sandbox paths are used for downloaded samples.
- Respect provider API limits and terms of service.

## Tests

```bash
pytest tests/ -q
```
