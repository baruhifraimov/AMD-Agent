# AGENTS.md

## Project

AMD-Agent is a Docker-first LangGraph pipeline for Windows PE malware collection,
static feature extraction, concept drift detection, capa/Ollama explainability,
and LightGBM retraining with MADAR replay.

Treat downloaded samples as hostile. Do not execute downloaded binaries.

## Current Architecture Notes

- The default Docker command is `/app/docker/amd-agent-run.sh`.
- `amd-agent-run.sh` runs preflight, runs bootstrap only when the trainable
  100/100 target or model bundle is not ready, then stays in `src.graph --daemon`.
- The graph is compiled in `src/graph.py` with a LangGraph `MemorySaver`.
- Source selection now goes through `src/collection/*` strategies.
- Bootstrap collection is deterministic and fast:
  - malware: `malwarebazaar` first,
  - benign: `sysinternals` / `github`,
  - dynamic CTI fallback only when primary malware discovery is dry.
- Steady-state malware collection routes through `ThreatIntelIngest`.
- Do not reintroduce the older `ThreatQueue`/standalone bridge design unless
  the project explicitly asks for that rollback.

## Threat Intel Flow

- `src/nodes/threat_intel_ingest.py` is the graph node for steady-state CTI.
- `src/intel/collector.py` discovers, polls, validates, and queues CTI hashes.
- `src/intel/threatingestor_artifacts.py` reads InQuest ThreatIngestor SQLite
  artifacts and returns normalized candidates for in-process validation.
- The ThreatIngestor sidecar is configured by `threatingestor_config.yml` and
  supervised by `docker/threatingestor-entrypoint.sh`.
- ThreatIngestor is skipped while collection phase is `bootstrap`; it is a
  steady-state sidecar, not the first 100/100 bootstrap source.
- Dynamic CTI uses `ddgs`/DuckDuckGo search as discovery only. It may extract
  hashes or allowlisted PE URLs, but arbitrary web URLs must not become direct
  binary downloads.
- Malware downloads should stay provider-controlled. MalwareBazaar remains the
  primary safe malware binary backend.

## Training And Model Readiness

- Initial training requires at least 100 active malware samples and 100 active
  benign samples with extracted features.
- Pending rows, corrupted rows, and rows without `features_json` do not count.
- `src.db.tracker.MalwareTracker.count_by_label()` is the trainable-count source
  of truth.
- `model.pkl` is only ready when `model_bundle_ready(load_bundle())` passes.
- Feature vectors currently contain 17 features. Old 15-feature model bundles
  should be considered stale and retrained.
- Retrain/cold-start must protect against single-class training splits.

## Data And Paths

- In Docker, durable data lives under `/data` and maps to `./data`.
- Main DB: `/data/malware_tracker.db`.
- ThreatIngestor artifacts DB: `/data/threatingestor_artifacts.db`.
- Models: `/data/models`.
- Figures/logs: `/data/figures` and `/data/evaluation_log.jsonl`.
- Sample statuses are `pending`, `active`, and `corrupted`.
- Rejected or malformed samples must be marked `corrupted` so they are not
  pulled repeatedly.

## Docker And Networking

- Docker runs on `malware_net`.
- `docker/entrypoint.sh` applies the egress guard with `iptables`.
- Compose grants `NET_ADMIN`; do not remove it unless replacing the network
  guard with an equivalent safeguard.
- `AMD_OLLAMA_BASE_URL` is the only Ollama base URL variable. Do not add a
  second Docker-only Ollama URL unless explicitly requested.
- Source changes are mounted into the container with `./src:/app/src:ro`, so
  Python source edits usually do not require a rebuild.
- Dockerfile, requirements, docker scripts, and config files copied into the
  image do require a rebuild.

## Common Commands

Use Docker for the most reliable runtime because the project targets Python 3.12:

```powershell
docker compose build
docker compose up --force-recreate
docker compose run --rm --entrypoint python amd-agent -m pytest
docker compose run --rm --entrypoint python amd-agent scripts/preflight_check.py
```

For local static checks:

```powershell
python -m compileall -q src tests
docker compose config --quiet
git diff --check
```

Manual graph modes:

```powershell
docker compose run --rm amd-agent python -m src.graph --once
docker compose run --rm amd-agent python -m src.graph --bootstrap
docker compose run --rm amd-agent python -m src.graph --daemon
```

## Environment

Important variables:

- `MALWAREBAZAAR_AUTH_KEY`: required for MalwareBazaar and abuse.ch fallbacks.
- `AMD_OLLAMA_BASE_URL`: Ollama endpoint, often a reachable VM/host IP.
- `AMD_BOOTSTRAP_MAX_RUNS`, `AMD_BOOTSTRAP_INTERVAL`: first-run bootstrap loop.
- `AMD_INTEL_INGEST_ENABLED`: enables the integrated CTI ingest node.
- `AMD_THREATINGESTOR_ENABLED`: enables sidecar artifact polling.
- `AMD_THREATINGESTOR_SLEEP_BOOTSTRAP`: sidecar sleep while bootstrap is active.
- `AMD_THREATINGESTOR_SLEEP_STEADY`: sidecar sleep after 100/100 is met.
- `AMD_ADWIN_DELTA`: drift sensitivity.

Keep `.env.example` aligned with any new runtime variables.

## Testing Guidance

- Prefer targeted tests for touched behavior.
- Run full pytest in Docker when dependencies are not installed locally.
- If local Python lacks dependencies, report that clearly instead of assuming
  tests passed.
- Preflight checks are in `scripts/preflight_check.py`.

## Editing Rules

- Preserve user changes in the worktree. Do not reset or checkout files unless
  explicitly requested.
- Keep Docker cache behavior in mind: add new dependencies to `requirements.txt`
  when possible; heavy stable dependencies belong in `requirements.base.txt`.
- Use structured parsers and existing helper APIs instead of ad hoc parsing when
  the project already provides them.
- Keep security-sensitive changes conservative. Never make arbitrary direct web
  downloads of binaries unless they go through the explicit allowlist and PE
  validation flow.
