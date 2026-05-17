# Replayable Datasets — Argus SOC Homelab

Sanitized JSON exports from live Elasticsearch telemetry generated during Argus stress test on 2026-05-16.

---

## Source

| Property | Value |
|---|---|
| Host | DESKTOP-MM1REM9 (Windows 10, 10.0.20.10) |
| Attack framework | Atomic Red Team (330 atomics installed) |
| Execution window | 16:45-17:16 UTC, 2026-05-16 |
| Cases formed | 6 (CASE-001 through CASE-006) |
| Total behaviors | 708 across all cases |
| EDR pipeline | Sysmon EID 1/10/11/13 via Elastic Agent → Elasticsearch |
| NDR pipeline | Suricata EVE via Filebeat 7.14.0 → Elasticsearch |

---

## Techniques Executed

| Technique | ID | Tactic |
|---|---|---|
| Process Discovery | T1057 | Discovery |
| System Information Discovery | T1082 | Discovery |
| Network Configuration Discovery | T1016 | Discovery |
| Network Connections Discovery | T1049 | Discovery |
| System Owner/User Discovery | T1033 | Discovery |
| PowerShell Execution | T1059.001 | Execution |
| Windows Command Shell | T1059.003 | Execution |
| Registry Run Key Persistence | T1547.001 | Persistence |
| Scheduled Task Creation | T1053.005 | Persistence |
| Local Account Creation | T1136.001 | Persistence |
| OS Credential Dumping (LSASS) | T1003.001 | Credential Access |
| Modify Registry | T1112 | Defense Evasion |

---

## Files

| File | Description | Behaviors | Size |
|---|---|---|---|
| argus-cases-2026-05-16.json | All 6 cases from case_builder.py output | 6 cases | 4.4KB |
| behaviors-CASE-004-2026-05-16.json | Primary demo case. 251 behaviors, full kill chain, cross-layer corroborated | 251 | 155KB |
| behaviors-CASE-005-2026-05-16.json | 53 behaviors. EXECUTION + DEFENSE_EVASION + DISCOVERY | 53 | 33KB |
| behaviors-CASE-006-2026-05-16.json | 52 behaviors. EXECUTION + PERSISTENCE + DISCOVERY | 52 | 32KB |
| argus-actions-2026-05-16.json | Analyst actions audit trail from investigation session | — | 1.4KB |

---

## Notes on Missing Data

CASE-001, CASE-002, and CASE-003 behavior exports are empty or near-empty due to an Elasticsearch index mapping constraint. These cases were written to an older index shard where `case_id.keyword` mapping was not yet applied. The behaviors exist in Elasticsearch but are not retrievable via the standard API query pattern.

CASE-004, CASE-005, and CASE-006 were written after the mapping fix and export cleanly.

Suricata EVE (NDR) data is not included in this dataset. The cross-layer corroboration for CASE-004 — 12 Suricata network events independently confirming PowerShell HTTP activity — requires a live pfSense Filebeat pipeline to replay meaningfully and cannot be represented as a static JSON export.

---

## Replaying the Dataset

To load this data into a fresh Argus instance:

```bash
# 1. Import cases
curl -X POST "http://localhost:9200/argus-cases/_bulk" \
  -H "Content-Type: application/json" \
  --data-binary @argus-cases-2026-05-16.json

# 2. Import behaviors (repeat for each file)
curl -X POST "http://localhost:9200/argus-behaviors/_bulk" \
  -H "Content-Type: application/json" \
  --data-binary @behaviors-CASE-004-2026-05-16.json

# 3. Restart case_builder.py to re-form case relationships
python case_builder.py

# 4. Open Argus frontend
# http://localhost:5173
```

Note: The exported JSON is in Argus API response format, not ES bulk format. You will need to transform it before bulk import. The cases and behaviors are fully self-contained and do not require the original Sysmon pipeline to be active.

---

## Related Artifacts

| Artifact | Location |
|---|---|
| IR-006 investigation report | `investigation-reports/IR-006/` |
| Sigma detection rules | `sigma-rules/` |
| Argus behavioral profiles | `argus/behavior_detector.py` |
| Attack scenario script | `argus/IR-001-Scenario.ps1` (excluded from repo via .gitignore) |
