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
| Argus API, behavior_detector, case_builder, and frontend run via a single docker compose up --build | README, Stack | Yes, containerized this session | Yes, confirmed clean build, all 6 services healthy, zero restarts | KEEP |
| Behavior detector maps Sysmon events to 44 MITRE rules | README, Key Achievements | Code exists in repo, confirmed at runtime | Re-verified during the PapaBear audit pass: README previously said 96, which was wrong. Ground truth checked two ways, a direct count of `BEHAVIOR_PROFILES` entries in `behavior_detector.py` (44) and the live daemon's own startup log (`Loaded 44 behavior enrichment profiles...`). `ARGUS.md` already said 44 correctly; README's three Argus-specific mentions were wrong and are now fixed. Note: README also separately and correctly references "96" for the unrelated historical `detection-rules/sysmon-custom-rules.ndjson` export, confirmed as a genuinely different artifact with 96 real entries, not touched | KEEP |
| Case builder groups behaviors into cases | README, Key Achievements | Code exists in repo | Confirmed working end to end against seeded data: correctly recomputes behavior_count and risk_score from real behaviors | KEEP |
| Argus frontend, React workstation shell with process tree, timeline, hunt workbench | README, Argus section | Code exists in repo | Production build passes clean (npm run build, re-verified from a fully deleted node_modules/dist). Case queue and behavior views confirmed displaying real seeded data. Hunt workbench and process tree confirmed running against seeded data too: both correctly report "no raw Sysmon telemetry available" (that telemetry isn't part of the seed set) instead of crashing or showing a raw exception, timeline confirmed in strict chronological order for CASE-004's 248 behaviors | KEEP |
| Full analyst action trail written to Elasticsearch | README, Key Achievements | Code exists in repo | Confirmed end to end: POST /api/actions returns a real action_id, GET /api/actions surfaces it, and a live write-read-refresh cycle was verified through the frontend proxy | KEEP |
| Hunt workbench with 7 ES\|QL templates | README, Key Achievements | Code exists in repo | Not yet confirmed runnable from fresh clone | BUILD (verify) |
| Claude Haiku integration for narration | README, Key Achievements | Code exists in repo | Low risk, design claim rather than infra claim | KEEP, verify later |
| Cross-layer correlation, 23 Sysmon EID 3 events matching 23 Suricata HTTP flows | README, Key Achievements, IR-005 | Evidence exists in IR-005 raw data | Historical result, not something a stranger reproduces live | PAST TENSE |

## Hermes

| Claim | Where stated | Exists today? | Reproducible from repo? | Decision |
|---|---|---|---|---|
| Hermes classifies NOISE vs SIGNAL | README references, prior pitch language, resume | Yes, rebuilt from scratch this session under `hermes/` | Yes: `python -m hermes.cli dry-run --scenario noise` and `--scenario signal` produce deterministic, evidence-cited decisions from fixture data. No LLM in the decision path, no external dependency. Verified with two runs of each scenario, byte-for-byte identical output | KEEP |
| Discord integration for querying Elasticsearch and Argus | Prior pitch language, LinkedIn | No, the original ran only on Node 2 and never entered this repo; the rebuild deliberately has no Discord dependency at all | No | CUT |
| Sample Hermes output (CASE-020 analysis, Sigma rule generation, threat hunting queries) | Discord chat log, `docs/HISTORICAL-LAB.md` reference | Yes, `hermes/legacy-output-examples/CASE-020-discord-output.md` now exists, containing the saved Discord output | Yes, readable as a static reference document. Not reproducible, it's a transcript, not code, and is explicitly marked as such | PAST TENSE, output only, no source, KEEP as reference material |

**Hermes rebuild note:** the original Hermes never made it into this repository and did not survive the Node 2 wipe, so this is a full rebuild, not a recovery. There was no legacy source to work from, only the Discord log's description of past output shape, and even that file (`hermes/legacy-output-examples/`) turned out not to actually exist in the repo when checked. Built this session:

- `hermes/state_manager.py`, `workflow_base.py`, `dispatcher.py`, `reporting.py`, `cli.py`, and two fixtures (`noise.json`, `signal.json`), all new code
- Decision rule is plain conditional logic in `dispatcher.py`: two or more independently-fired signal categories (encoded execution, persistence, EDR+NDR network corroboration) yields SIGNAL, fewer yields NOISE. No LLM call anywhere in the decision path
- `StateManager.add_reason()` enforces the evidence-citation rule at runtime: a workflow citing an `evidence_id` not present in that run's evidence raises, rather than relying on convention
- Verified determinism the same way the seed loader was verified: ran both scenarios twice each and diffed the output, byte-identical both times
- Verified no external dependency: grepped the whole package for Discord, Kali, pfSense, WinRM, and any network-calling code; the only match was a docstring explaining why it doesn't need Discord
- Runs entirely from the package: `python -m hermes.cli dry-run --scenario noise`, no bot process, no server, no token

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
| IR-006, host discovery and PowerShell HTTP payload retrieval investigated inside Argus, cross-layer corroborated | README, Investigation Reports | Yes, corrected this session | Every remaining claim traces to a specific screenshot, a cross-referenced confirmed number from another section, or is explicitly framed as recommendation rather than finding | KEEP |

**IR-006 correction note:** the report originally claimed a five-stage attack (recon, payload retrieval, blocked LOLBin execution, encoded PowerShell, and persistence via registry run key and scheduled task), with five specific numbers (four PIDs and a connection count) that directly contradicted the report's own attached screenshots. Corrected this session:

- Fixed 5 factual errors where the report text disagreed with its own cited screenshots (whoami.exe, HOSTNAME.EXE, net1.exe, systeminfo.exe PIDs, and the rundll32.exe outbound connection count, which was overstated at 3 when the evidence showed 1)
- Cut the three unevidenced stages (blocked certutil/AppControl, encoded PowerShell execution, registry Run key and scheduled task persistence), none of which had a screenshot, raw event, or any evidence path, since the raw telemetry only ever lived on the now-decommissioned Node 2 and was never captured to `raw-events/` for this report, unlike IR-002 through IR-005
- Removed a false footnote claiming raw events existed under `raw-events/`, since that folder was never created for this report
- Updated the executive summary to explicitly state the report only independently verifies discovery and payload retrieval, and does not confirm what specifically drove the case's own PERSISTENCE classification tag (that tag itself is kept, since it is Argus's own output visible in a screenshot, not a claim this report is making)
- Dropped T1053.005 (Scheduled Task) from the MITRE list, the only technique tied exclusively to a cut stage
- Removed a detection gap (AppControl/certutil) that presupposed a now-cut claim as fact, renumbered the remaining gap
- Left minor environmental description (Kali Linux, python3 http.server, Windows 10 22H2) as-is, these are background context consistent with HISTORICAL-LAB.md, not investigative findings being claimed as confirmed
- Fixed a minor internal inconsistency where a timeline row implied exact-second precision while its own footnote called the stage "approximate"

The report is now smaller than the original version but every remaining line is independently verifiable from what's in the repository.

## Datasets

| Claim | Where stated | Exists today? | Reproducible from repo? | Decision |
|---|---|---|---|---|
| Seed datasets in `datasets/` are usable demo data | Repository structure | Files exist | Confirmed: a deterministic seed loader (`seed_argus.py`) now loads them, recomputes case metadata from real behavior data rather than trusting stale stored counts, and correctly discards or remaps orphaned records. See note below on data quality issues found | KEEP (loader), see note |

**Data quality note, found in an earlier session:** the original export in `datasets/` had real integrity problems, not just a schema mismatch. One case (CASE-011) referenced in the actions dataset does not exist anywhere in the cases file. Two cases (CASE-002, CASE-003) had stored behavior counts of 51 and 54 but zero real behaviors on disk. Seven of ten seeded analyst actions pointed at these broken references and are now correctly dropped by the loader rather than silently indexed. Three actions had genuine analyst content referencing stale behavior IDs from a since-regenerated index; these were remapped onto real current behaviors rather than discarded. Note: the dangling CASE-011 action found in this dataset is the same CASE-011 referenced in IR-006, IR-006's own screenshot confirms it as a real historical action, just from an environment that predates the current seed data snapshot, not fabricated data.

---

## Verified This Session (final audit against PapaBear's original feedback)

Went through every specific point in PapaBear's original feedback message and re-verified each live, not from memory of prior sessions. Full method: deleted `node_modules`/`dist` and ran a clean frontend build; deleted the Elasticsearch Docker volume (not just the containers) and ran `docker compose up --build` as a genuine first-clone simulation; ran both Hermes scenarios live; ran a live analyst-action write-read cycle; re-checked IR-006 against its actual screenshots, not the prior session's notes about them; grepped the whole repo for stale claims.

Two real findings came out of this pass that hadn't been caught before, both now fixed:

- `argus/ARGUS.md` had never been touched during the whole remediation. Its opening two lines and a section header still described Argus as running on live infrastructure ("It sits over two live telemetry pipelines... two old Dell boxes") and still referenced IR-006's original five-stage framing, which had already been cut for lacking evidence. Rewritten to match how README and HISTORICAL-LAB.md already frame this: Argus the software runs today via Docker Compose, the original two-node telemetry collection it was built against is decommissioned.
- README claimed Argus's behavior detector uses 96 detection rules, in three places. Checked against ground truth two ways (direct code count, live daemon log output): the real number is 44. Two of those three mentions were actually wrong and are now fixed; the third "96" mention in README turned out to be a legitimately different, separate artifact (the historical `detection-rules/sysmon-custom-rules.ndjson` export, confirmed to genuinely contain 96 entries) and was correctly left alone rather than incorrectly "fixed" to match the wrong number.

`scripts/verify-demo.sh` run fresh after both fixes: 10/10 PASS.

## Verified This Session (Hermes rebuild)

- Confirmed no legacy Hermes source or `hermes/legacy-output-examples/` exists anywhere in the repository before starting, so this was built as new code, not recovered
- Built the full `hermes/` package to the required structure: dispatcher, workflow base, state manager, reporting, CLI, and two fixtures
- Verified determinism (two runs per scenario, byte-identical diff) and zero external dependency (grepped for Discord/Kali/pfSense/WinRM/network calls)
- Found the HISTORICAL-LAB.md reference to `hermes/legacy-output-examples/` pointed at a path that didn't exist, logged it, then closed it out: `hermes/legacy-output-examples/CASE-020-discord-output.md` now contains the actual saved Discord transcript, with a header marking it historical, not reproducible, no source code for the agent that produced it

## Verified This Session (IR-006 correction)

- Went claim by claim through IR-006 against its 7 screenshots and found 5 factual contradictions plus one silently dropped result row, all corrected
- Made the judgment call to cut unevidenced stages entirely rather than caveat them, on the reasoning that a caveat next to an unverifiable claim still asks a stranger to trust an assertion the repo can't back, which is the exact pattern this whole remediation exists to fix
- Ran a full second verification pass after the cuts to confirm no orphaned references remained (MITRE list, detection gaps, environment table all checked and corrected)

## Verified In Prior Session (Pydantic contracts, action_id fix, seed loader)

- Added Pydantic response models to all 5 relevant GET endpoints (Case, Behavior, GroupedBy, BlastRadius, BurstWindow) and a request model (ActionIn) with a Literal type for valid actions, so an invalid action now returns a clean 422 instead of reaching the handler
- Fixed `action_id` missing from both the POST response and the GET list, confirmed with a live write-read-refresh cycle through the frontend's own proxy
- Built `seed_argus.py`, a deterministic seed loader verified to produce identical output across repeated runs
- Frontend confirmed serving real seeded case and behavior data through its own `/api` proxy path, not just the API directly

## Immediate Priorities From This Inventory

1. Verify the remaining Argus screens (hunt workbench, process tree, timeline) against the new seed data, currently unconfirmed since the fix.
2. Run the full automated verification pass and a clean-room test (someone with no context, given only the repo URL and README).
3. Update the README's "What you can run today, now" section to reflect everything now confirmed working, including Hermes.
