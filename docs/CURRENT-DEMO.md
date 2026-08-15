# Current Demo: What Runs Today

This document describes only what a person can actually clone, run, and verify from this repository right now. If something is not listed here, do not assume it runs. For the original live lab this project is based on, see [HISTORICAL-LAB.md](HISTORICAL-LAB.md).

This file is updated as remediation work lands. Until the portable demo is complete, treat this as a work in progress log, not a finished feature list.

---

## Status

This section is filled in as each piece is verified working from a clean environment. Nothing below is checked until it has actually been tested that way.

- [x] Elasticsearch runs via Docker Compose and reports healthy status
- [x] Kibana runs via Docker Compose and is reachable
- [x] Argus API, behavior_detector, case_builder, and frontend run via a single `docker compose up --build`, no manual multi-terminal startup
- [x] Seed data loads via a deterministic loader (`seed_argus.py`) and produces identical output across repeated runs
- [x] Argus API starts and serves requests, with Pydantic-validated request and response models on cases, behaviors, and actions endpoints
- [x] Argus frontend builds cleanly with `npm ci && npm run build`
- [x] Argus frontend displays seeded cases and behaviors correctly, confirmed through its own `/api` proxy path
- [x] Analyst actions can be recorded and persist after a refresh, confirmed with a live write-read-refresh cycle including a real `action_id` returned and surfaced
- [ ] Hunt workbench, process tree, and timeline screens verified against the new seed data
- [x] Hermes exists in this repository as real code, under `hermes/`
- [x] Hermes produces a deterministic NOISE decision from a fixture
- [x] Hermes produces a deterministic SIGNAL decision from a fixture
- [ ] IR-006 raw-events folder backfilled to match IR-002 through IR-005
- [ ] A person with no prior context can clone this repo and reach a working demo using only the README (clean-room test not yet run)

## Prerequisites

- Docker Desktop with WSL2 backend (Windows) or Docker Engine (Linux/Mac)
- Git

## Quick Start

```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
cd path\to\soc-homelab
docker compose up --build -d
```

Confirm all services are healthy:

```powershell
docker compose ps
```

All six containers (elasticsearch, kibana, argus-api, behavior_detector, case_builder, frontend) should show `Up` with `argus-api` and `elasticsearch` marked `healthy`.

Load the seed data:

```powershell
docker compose run --rm seed
```

This is safe to run multiple times, it deletes and recreates the demo indices from the source files in `datasets/` each time, and produces identical results on every run.

Confirm the demo is serving real data:

```powershell
curl http://localhost:8000/api/cases
curl http://localhost:5173/api/cases
```

Both should return the same seeded cases. The frontend is reachable at `http://localhost:5173`.

Run Hermes (no Docker service needed, it's a standalone CLI, not a daemon; run from the repo root, not from inside `hermes/`):

```powershell
python -m hermes.cli dry-run --scenario noise
python -m hermes.cli dry-run --scenario signal
```

Each prints a JSON decision (`{"decision": "NOISE"|"SIGNAL", "reasons": [...], "evidence_ids": [...]}`) computed deterministically from the fixture in `hermes/fixtures/`. No Discord, no external service, no live environment involved.

## Known Data Notes

The seed loader (`seed_argus.py`) recomputes case metadata from the actual seeded behaviors rather than trusting the stored counts in the original export, which had some integrity issues (a dangling case reference, two cases with stored counts that didn't match zero real behaviors on disk). This is handled automatically and logged when the seeder runs, nothing to do manually.

## What Is Not Included

- The original two node Proxmox lab. See [HISTORICAL-LAB.md](HISTORICAL-LAB.md).
- Live attacker or victim VMs. Telemetry in the demo comes from seeded fixture data, not live attack execution.
- Kali, pfSense, and Windows victim infrastructure. None of this is required to run or evaluate the demo.
- Hermes is present and runnable (see Quick Start above) but is a standalone CLI dry-run tool, not wired into `docker compose up` as a service, and not integrated with Argus's live case data. It evaluates its own fixtures independently.
