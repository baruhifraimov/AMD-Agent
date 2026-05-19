# AMD-Agent: Autonomous Continual Malware Detection

AMD-Agent is a LangGraph-based malware analysis pipeline for collecting Windows PE samples, extracting static features, detecting concept drift, explaining suspicious drift with capa + Ollama, and retraining a LightGBM classifier with MADAR replay.

The project is designed for isolated execution in Docker or a malware-analysis VM. Do not run downloaded binaries.

## Current Architecture

```text
START
  -> SourceSelector
      -> benign path: SourceDiscovery
      -> malware path: ThreatQueue
          -> queue has hashes: BinaryFetch
          -> queue empty: SourceDiscovery
  -> BinaryFetch
  -> DataValidation
  -> FeatureExtraction
  -> DriftMonitor
      -> no drift: ClassifierInference -> END
      -> drift: ActiveLearningExplain -> ModelRetrain -> END
```

### Main components

- `SourceSelector`: asks Ollama to choose source strategy when available, with deterministic fallback based on malware/benign balance in SQLite.
- `ThreatQueue`: consumes pending hashes inserted by ThreatIngestor. Corrupted hashes are skipped.
- `SourceDiscovery`: discovers samples from one or more registered providers.
- `BinaryFetch`: downloads through each candidate's own provider, not a global provider.
- `DataValidation`: checks MZ header, validates `PE\0\0` at `e_lfanew`, verifies filename SHA256, de-duplicates, skips known corrupted hashes, and syncs SQLite status.
- `FeatureExtraction`: extracts 15 PE features using `pefile`; parse failures are triaged and marked `corrupted`.
- `DriftMonitor`: uses River ADWIN over section entropy.
- `ClassifierInference`: scores samples with LightGBM and FPR-aware thresholding.
- `ActiveLearningExplain`: runs `capa -j -r <rules_dir>` and asks Ollama to produce a semantic drift report.
- `ModelRetrain`: retrains with MADAR replay buffer. Single-class retrain batches are skipped safely.
- `Evaluation`: runs TESSERACT-style chronological evaluation and computes AUT.

## Data Sources

### Malware

- MalwareBazaar API:
  - recent PE metadata discovery,
  - SHA256-based sample download,
  - password-protected ZIP extraction using password `infected`.

- Dynamic CTI discovery:
  - DuckDuckGo search,
  - public CTI page fetching with strict byte truncation,
  - SHA256 extraction with surrounding evidence,
  - semantic hash filtering through Ollama when available.

Dynamic CTI uses a Hybrid Strict policy: CTI pages are used only as evidence for hashes. Arbitrary CTI URLs are not used for binary download.

### Benign

- Sysinternals live directory.
- GitHub release assets from curated benign repositories.
- Optional local benign corpus under `data/benign`.

## Safety And Persistence

- Docker runs on isolated `malware_net`.
- `docker/entrypoint.sh` blocks egress to private/local subnets with `iptables`.
- `docker-compose.yml` grants `NET_ADMIN`, required for those `iptables` rules.
- Docker allows the configured Ollama endpoint before private subnet blocking.
- SQLite uses WAL mode to reduce lock errors with external ThreatIngestor writes.
- LangGraph uses `MemorySaver` checkpointer with default thread id `amd-agent-default`.
- Downloaded samples are stored under sandbox paths and are never executed.

## SQLite Sample Status

`samples` rows include:

| Column | Meaning |
|---|---|
| `sha256` | sample hash |
| `file_path` | sandbox path; empty string for pending queue rows |
| `acquired_at` | acquisition timestamp |
| `features_json` | extracted static PE features |
| `label` | `1` malware, `0` benign |
| `prediction` | LightGBM malicious probability |
| `anomaly_score` | reserved anomaly score |
| `status` | `pending`, `active`, or `corrupted` |
| `reject_reason` | raw rejection/parse reason |
| `rejected_at` | rejection timestamp |

ThreatQueue only consumes pending malware rows where `file_path=''` and `status` is `pending` or `active`. Rows marked `corrupted` are not retried.

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

Base dependencies include:

- `langgraph`, `pydantic`
- `langchain-ollama`, `langchain-core`
- `httpx`, `beautifulsoup4`, `duckduckgo-search`
- `pefile`, `pyzipper`, `flare-capa`
- `river`, `lightgbm`, `scikit-learn`
- `numpy`, `pandas`, `joblib`, `matplotlib`
- `pytest`, `pytest-httpx`

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
| `AMD_BENIGN_PROVIDER` | force benign provider: `sysinternals` or `github` |
| `AMD_ALLOW_LOCAL_BENIGN` | ingest `data/benign/*` as label `0` |
| `AMD_THREAT_QUEUE_ENABLED` | enable/disable ThreatIngestor queue consumption |
| `AMD_CAPA_RULES_DIR` | capa rules directory passed with `-r` |
| `AMD_REPORT_LANGUAGE` | language for Ollama drift report |
| `AMD_CTI_SEARCH_LIMIT` | max search results per CTI query |
| `AMD_CTI_PAGE_LIMIT` | max CTI pages per discovery run |
| `AMD_CTI_PAGE_MAX_BYTES` | max bytes read from each CTI page |
| `AMD_CTI_REQUEST_TIMEOUT` | CTI HTTP timeout |

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

Run the default Docker bootstrap. This repeatedly collects samples until the
initial model is trained or `AMD_BOOTSTRAP_MAX_RUNS` is reached:

```powershell
docker compose up --force-recreate
```

Run daemon:

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

## ThreatIngestor Integration

ThreatIngestor may run as a separate process and write pending hashes into SQLite.

Template:

```powershell
copy threatingestor_config.yml.example threatingestor_config.yml
threatingestor -c threatingestor_config.yml
```

Expected pending row contract:

| Column | Value |
|---|---|
| `sha256` | 64-char SHA256 |
| `file_path` | empty string |
| `label` | `1` |
| `status` | `pending` |
| `acquired_at` | timestamp |

## Evaluation

TESSERACT-style evaluation is implemented in `src/evaluation/tesseract.py`.

It uses:

- chronological train/validation/test splits,
- accuracy, precision, recall, FPR,
- dynamic threshold targeting `TARGET_FPR = 0.001`,
- AUT (`Area Under Time`) over historical accuracy,
- performance plot at `FIGURES_DIR/performance_decay.png`.

Local default figure path:

```text
report/figures/performance_decay.png
```

Docker figure path:

```text
/data/figures/performance_decay.png
```

The LaTeX report references `figures/performance_decay.png` and will not fail if the plot is not generated yet.

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

WAL mode is enabled. If locks persist, ensure ThreatIngestor and AMD-Agent point to same DB path and no long-lived manual SQLite shell holds a transaction.

## Security Notes

- Do not execute samples.
- Use a VM or Docker.
- Treat `data/sandbox` as malicious.
- Keep MalwareBazaar and GitHub tokens private.
- Respect source rate limits; Dynamic CTI includes query jitter and page-size truncation.
