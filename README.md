# AMD-Agent — Autonomous Continual Malware Detection

LangGraph pipeline that autonomously ingests PE samples from the internet (malware + benign), extracts static features with `pefile`, detects concept drift via River ADWIN, classifies with LightGBM, and retrains using MADAR replay.

## Architecture

```
START → SourceSelector → SourceDiscovery → BinaryFetch → DataValidation
      → FeatureExtraction → DriftMonitor ─┬─ (no drift) → ClassifierInference → END
                                          └─ (drift)    → ActiveLearningExplain → ModelRetrain → END
```

**PE sources (pluggable):**
- `malwarebazaar` — recent malware PE (label=1)
- `sysinternals` — Microsoft Sysinternals live `.exe` (label=0)
- `github` — release assets from curated repos (label=0)

`SourceSelector` reads SQLite label counts and picks malware vs benign to keep FPR tuning viable.

## Requirements

- Python 3.12+
- MalwareBazaar Auth-Key from [auth.abuse.ch](https://auth.abuse.ch/)
- Optional `GITHUB_TOKEN` for GitHub Releases benign fetching

## Setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # set MALWAREBAZAAR_AUTH_KEY
```

## Run

**Single pass (default):**
```bash
export PYTHONPATH=.
python -m src.graph --once
```

**Continuous scheduler (daemon):**
```bash
export PYTHONPATH=.
export AMD_SCHED_ENABLED=1
export AMD_SCHED_INTERVAL=1800   # seconds between runs
python -m src.graph --daemon
```

Or with YAML overrides:
```bash
cp scheduler.yaml.example scheduler.yaml
python -m src.graph --daemon --config scheduler.yaml
```

### Scheduler configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AMD_SCHED_ENABLED` | `0` | Enable daemon mode |
| `AMD_SCHED_INTERVAL` | `1800` | Seconds between runs |
| `AMD_SCHED_MAX_RUNS` | (empty) | Stop after N runs |
| `AMD_SCHED_RUN_ON_START` | `1` | Run immediately on start |
| `AMD_SCHED_JITTER` | `60` | Random extra sleep per interval |
| `AMD_SCHED_ERROR_BACKOFF` | `60` | Base backoff after failure |
| `AMD_SCHED_MAX_BACKOFF` | `3600` | Max backoff cap |
| `AMD_BENIGN_PROVIDER` | (empty) | Force `sysinternals` or `github` |
| `AMD_ALLOW_LOCAL_BENIGN` | `0` | Also ingest `data/benign/*.bin` |

## VM / sandbox

Run inside an isolated VM (recommended). Samples are static-parsed only (never executed). Docker is optional.

## Evaluation (TESSERACT)

```bash
python -c "
from src.evaluation import run_tesseract_eval, append_eval_log, plot_performance_decay
m = run_tesseract_eval()
if m: append_eval_log(m); plot_performance_decay(); print(m)
"
```

## Adding a new PE source

1. Subclass `PESourceProvider` in `src/sources/`.
2. Implement `discover()` and `download()`.
3. Register in `src/sources/registry.py` → `build_default_registry()`.

## Tests

```bash
pytest tests/ -q
```

## Security

- Live malware handling — isolated environment only.
- Respect MalwareBazaar [API rate limits](https://bazaar.abuse.ch/faq/#api-limit).
