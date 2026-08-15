# Current Demo: What Runs Today

This document describes only what a person can actually clone, run, and verify from this repository right now. If something is not listed here, do not assume it runs. For the original live lab this project is based on, see [HISTORICAL-LAB.md](HISTORICAL-LAB.md).

This file is updated as remediation work lands. Until the portable demo is complete, treat this as a work in progress log, not a finished feature list.

---

## Status

This section will be filled in as each piece is verified working from a clean clone. Nothing below is claimed until it has actually been tested that way.

- [ ] Elasticsearch runs via Docker Compose and reports healthy status
- [ ] Kibana runs via Docker Compose and is reachable
- [ ] Seed data loads and satisfies the API's data contracts
- [ ] Argus API starts and serves requests
- [ ] Argus frontend builds cleanly with `npm ci && npm run build`
- [ ] Argus frontend displays seeded cases correctly
- [ ] Analyst actions can be recorded and persist after a browser refresh
- [ ] Hermes exists in this repository as real code
- [ ] Hermes produces a deterministic NOISE decision from a fixture
- [ ] Hermes produces a deterministic SIGNAL decision from a fixture
- [ ] A person with no prior context can clone this repo and reach a working demo using only the README

## Prerequisites

- Docker Desktop with WSL2 backend (Windows) or Docker Engine (Linux/Mac)
- Git

## Quick Start

This section will contain the exact commands to bring up the demo once the Docker Compose setup for Argus and Hermes is complete. Right now, only the Elasticsearch and Kibana stack is confirmed running:

```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
cd path\to\soc-homelab
docker compose -f docker/elastic/docker-compose.yml up -d
```

Confirm Elasticsearch is healthy:

```powershell
docker exec elasticsearch curl -s -u "elastic:<password>" http://localhost:9200/_cluster/health
```

A healthy response returns JSON with `"status":"green"` or `"status":"yellow"`.

Argus and Hermes startup instructions will be added here once they are containerized and verified from a clean clone.

## What Is Not Included

- The original two node Proxmox lab. See [HISTORICAL-LAB.md](HISTORICAL-LAB.md).
- Live attacker or victim VMs. Telemetry in the demo comes from seeded fixture data, not live attack execution.
- Kali, pfSense, and Windows victim infrastructure. None of this is required to run or evaluate the demo.
