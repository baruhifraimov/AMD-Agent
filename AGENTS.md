# AGENTS.md

## Agent Rule

AMD-Agent is a Docker-first LangGraph pipeline for  PE malware collection,
static feature extraction, concept drift detection.

Make sure to be consice with the project, use /graphify to understand connections, make sure its OOP and SOLID and neat coding enabled.

if the source file is over 500 code you need to check yourself if its neat code and on SOLID, if not needs to understand smartly how to seperate, make sure to make a smart folder construction. folder construction should be smart and precise that the user/developer will be easy for him.


## Data And Paths

- In Docker, durable data lives under `/data` and maps to `./data`.
- Main DB: `/data/malware_tracker.db`.
- ThreatIngestor artifacts DB: `/data/threatingestor_artifacts.db`.
- Models: `/data/models`.
- Figures/logs: `/data/figures` and `/data/evaluation_log.jsonl`.
- Sample statuses are `pending`, `active`, and `corrupted`.
- Rejected or malformed samples must be marked `corrupted` so they are not
  pulled repeatedly.

## Environment

Keep `.env.example` aligned with any new runtime variables.

