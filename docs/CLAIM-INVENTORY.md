# Claim Inventory

Every public claim made about this project, where it appears, whether it exists today in a form a stranger can verify, and a decision.

Decisions:

- **KEEP**: true today, a stranger can verify it by cloning and running what is here
- **BUILD**: not yet true, must be built before it is claimed publicly again
- **CUT**: remove from all public text until it moves to KEEP
- **PAST TENSE**: real, but historical, reframed as something that was done rather than something that currently runs

Nothing marked CUT should be restated anywhere, README, resume, LinkedIn, or spoken in an interview, until it is rebuilt and moved to KEEP.

---

## Argus and Elastic Core

| Claim | Where stated | Exists today? | Reproducible from repo? | Decision |
|---|---|---|---|---|
| Elasticsearch and Kibana run via Docker Compose | README, Stack | Yes | Yes, confirmed via clean install and health check | KEEP |
| Behavior detector maps Sysmon events to 96 MITRE rules | README, Key Achievements | Code exists in repo | Not yet confirmed running end to end from a fresh clone | BUILD (verify) |
| Case builder groups behaviors into cases | README, Key Achievements | Code exists in repo | Not yet confirmed end to end from fresh clone | BUILD (verify) |
| Argus frontend, React workstation shell with process tree, timeline, hunt workbench | README, Argus section | Code exists in repo | Frontend does not currently complete a clean production build | BUILD |
| Full analyst action trail written to Elasticsearch | README, Key Achievements | Code exists in repo | Depends on seed data satisfying API contracts, not yet confirmed | BUILD |
| Hunt workbench with 7 ES\|QL templates | README, Key Achievements | Code exists in repo | Not yet confirmed runnable from fresh clone | BUILD (verify) |
| Claude Haiku integration for narration | README, Key Achievements | Code exists in repo | Low risk, design claim rather than infra claim | KEEP, verify later |
| Cross-layer correlation, 23 Sysmon EID 3 events matching 23 Suricata HTTP flows | README, Key Achievements, IR-005 | Evidence exists in IR-005 raw data | Historical result, not something a stranger reproduces live | PAST TENSE |

## Hermes

| Claim | Where stated | Exists today? | Reproducible from repo? | Decision |
|---|---|---|---|---|
| Hermes classifies NOISE vs SIGNAL | README references, prior pitch language, resume | No, code was never committed and did not survive the Node 2 wipe | No | CUT until BUILD is complete, then KEEP |
| Discord integration for querying Elasticsearch and Argus | Prior pitch language, LinkedIn | No, ran only on Node 2, not in repo | No | CUT |
| Sample Hermes output (CASE-020 analysis, Sigma rule generation) | Discord chat log | Yes, saved as reference | Not reproducible, output only, no source | PAST TENSE, store under `hermes/legacy-output-examples/` |

## Infrastructure

| Claim | Where stated | Exists today? | Reproducible from repo? | Decision |
|---|---|---|---|---|
| Two node Proxmox range with pfSense, Kali, Windows victim | README, Architecture Overview, Architecture Detailed | No, Node 2 was wiped, Proxmox not reinstalled | No | PAST TENSE, see HISTORICAL-LAB.md |
| Background automation, Atomic Red Team every 30 minutes via Task Scheduler | README, Key Achievements | No, ran on the decommissioned victim VM | No | PAST TENSE |
| Custom Filebeat pipeline fix on pfSense FreeBSD | README, Pipeline Engineering | Yes, as historical work, documented in IR reports | Not reproducible without the pfSense VM | PAST TENSE |
| Custom Suricata rule SID 9000001 | README, Detection Engineering | Yes, rule file exists in repo | Rule itself is real and inspectable, but not currently deployed against live traffic | PAST TENSE for deployment, KEEP for the rule artifact itself |

## Investigation Reports

| Claim | Where stated | Exists today? | Reproducible from repo? | Decision |
|---|---|---|---|---|
| IR-001 through IR-005, full kill chain, Defender on throughout | README, Investigation Reports | Yes, reports and raw evidence exist in repo | Evidence-backed, historical simulation | KEEP as historical evidence, PAST TENSE for any live claim |
| IR-006, complete Argus investigation validated against live telemetry | README, Investigation Reports | Report exists, but evidence depth does not match IR-002 through IR-005 | Partial, raw evidence in IR-006 is thinner than earlier reports | NEEDS REVIEW, trim claims to match actual evidence depth before marking KEEP |

## Datasets

| Claim | Where stated | Exists today? | Reproducible from repo? | Decision |
|---|---|---|---|---|
| Seed datasets in `datasets/` are usable demo data | Repository structure | Files exist | Do not currently satisfy what the Argus API expects | BUILD, fix data contracts |

---

## Immediate Priorities From This Inventory

1. Fix seed data in `datasets/` so it satisfies the API contracts. This likely unblocks the analyst action trail and hunt workbench claims at once.
2. Get the Argus frontend to a clean production build.
3. Rebuild Hermes as a minimal, deterministic dry-run producing NOISE and SIGNAL decisions from fixtures, using the CASE-020 Discord output as a reference for expected shape and format.
4. Review IR-006 line by line against its raw evidence folder, trim any claim not directly supported.
5. Once each item above is verified working from a clean clone, move its status from BUILD to KEEP here and reflect it in `CURRENT-DEMO.md`.
