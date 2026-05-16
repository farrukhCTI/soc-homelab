# SOC Homelab: Detection & Incident Response

**Focus:** SOC Analyst | Detection Engineering | Incident Response

This lab demonstrates how a single network alert can be expanded into a full kill chain investigation using endpoint telemetry and cross-layer correlation. It also hosts **Argus**, a custom SOC investigation console built on top of the Elastic Stack.

---

## Contents

- [How to Review This Project](#how-to-review-this-project)
- [What This Demonstrates](#what-this-demonstrates)
- [Argus: SOC Investigation Console](#argus-soc-investigation-console)
- [Investigation Reports](#investigation-reports)
- [Kibana Dashboards](#kibana-dashboards)
- [Kill Chain Narrative](#kill-chain-narrative-ir-002-to-ir-005)
- [Key Achievements](#key-achievements)
- [Architecture Overview](#architecture-overview)
- [Architecture Diagram](#architecture-diagram)
- [Architecture Detailed](#architecture-detailed)
- [Detection Pipelines](#detection-pipelines)
- [Detection Engineering](#detection-engineering)
- [Repository Structure](#repository-structure)
- [Stack](#stack)
- [Hardware](#hardware)
- [Author](#author)

---

## How to Review This Project

1. Start with **IR-005**: full kill chain reconstruction from a single NDR alert anchor
2. Refer to **IR-002 through IR-004** for individual attack stages
3. See **IR-006** for a complete end-to-end investigation conducted inside Argus: process tree, cross-layer corroboration, entity pivot, and analyst action trail
4. See **[ARGUS.md](argus/ARGUS.md)** for the SOC investigation console built on top of this lab
5. Use screenshots and raw events in each report folder for validation

---

## What This Demonstrates

- Correlated independent NDR and EDR telemetry to validate C2 activity across both network and endpoint layers
- Reconstructed a full attack kill chain from a single Suricata alert using ProcessGuid chaining and timestamp pivoting
- Engineered custom detection rules where standard tooling had documented blind spots
- Incident response investigations mapped to MITRE ATT&CK with detection gap analysis and remediation design
- Pipeline engineering to solve real infrastructure limitations, not just configure existing tools
- Built Argus, a full SOC investigation console on top of the existing Elastic Stack with AI-assisted analyst briefings, process tree reconstruction, hunt workbench, and analyst action trail

---

## Argus: SOC Investigation Console

Argus is a behavior-driven SOC investigation console built on top of this lab's Elastic Stack. It runs three Python daemons continuously: a behavior detector that polls Sysmon telemetry every 60 seconds and maps events to 96 MITRE-mapped detection rules, a case builder that groups behaviors into cases using a 10-minute sliding window with density requirements, and a FastAPI backend serving a React frontend.

The frontend is a workstation-style layout: case queue on the left, process tree investigation workspace in the center, AI briefing and analyst actions on the right. Claude Haiku is integrated at three points: case summaries, behavior-level briefings with next steps, and a hunt workbench co-pilot. All AI output is narration only. Detection and scoring are fully deterministic.

**See [ARGUS.md](argus/ARGUS.md) for full documentation and screenshots.**

---

## Investigation Reports

IR-001 through IR-005 cover a connected kill chain simulating LOLBin-based post-compromise operator behavior on a defended Windows 10 endpoint (Defender ON, UAC ON throughout). IR-006 is a separate controlled simulation conducted entirely inside Argus, demonstrating the full investigation workflow from case triage through cross-layer corroboration and hunt pivot.

| Report | Title | MITRE TTPs | Platform | Status |
|---|---|---|---|---|
| IR-001 | Tool Transfer and Persistence | T1105, T1053.005, T1218.003 | Kibana | Complete |
| IR-002 | Reconnaissance and Host Discovery | T1046, T1082, T1033, T1016 | Kibana | Complete |
| IR-003 | Encoded PowerShell Execution and C2 Beaconing | T1059.001, T1027, T1071.001, T1105 | Kibana | Complete |
| IR-004 | Defense Evasion and Persistence | T1218.005, T1547.001, T1562.001, T1036 | Kibana | Complete |
| IR-005 | Correlated Kill Chain Hunt | Cross-layer, all TTPs | Kibana | Complete |
| IR-006 | PowerShell-Originated Payload Retrieval and Persistence | T1059.001, T1105, T1053.005, T1082, T1016, T1049, T1033 | Argus | Complete |

IR-005 is the Kibana-era centrepiece: a pure analyst exercise reconstructing the full kill chain from a single NDR alert by pivoting on timestamp, chaining ProcessGuid relationships, and validating activity independently across both EDR and NDR datasets.

IR-006 is the Argus-era centrepiece: a controlled simulation investigated entirely inside the Argus console. CASE-011 (26 behaviors, risk 5,109) was triaged through process tree analysis, cross-layer corroboration (6 Suricata events independently confirming EDR-observed PowerShell HTTP activity), entity pivot to the hunt workbench, and analyst action logging. It is the first investigation to demonstrate the full Argus workflow end to end against live telemetry.

---

## Kibana Dashboards

Five Kibana dashboards visualize the kill chain data across both pipelines. Dashboard 4 (Cross-Layer Correlation) is the portfolio centrepiece: Sysmon and Suricata independently recorded the same 23 C2 connections with no shared data path. See [DASHBOARDS.md](DASHBOARDS.md) for the full dashboard index, panel breakdown, and screenshots.

---

## Kill Chain Narrative (IR-002 to IR-005)

```
IR-002              IR-003                  IR-004                    IR-005
Reconnaissance  ->  Encoded Execution   ->  Persistence           ->  Correlated Hunt
& Discovery         & C2 Beaconing          & Defense Evasion         Full Kill Chain

T1046, T1082        T1059.001, T1027        T1218.005, T1547.001      Cross-layer
T1033, T1016        T1071.001, T1105        T1562.001, T1036          timeline
```

The investigation begins with a network scan alert and expands through endpoint telemetry to uncover execution, persistence, and defense evasion activity across a 2 hour 37 minute dwell window.

**Kill chain window:** 2026-04-02 14:41 to 17:18
**T=0:** Suricata SID 9000001 fires on Nmap SYN scan at 14:41:40
**Endpoint:** DESKTOP-MM1REM9 (10.0.20.10), Windows 10 Pro 22H2

---

## Key Achievements

### Detection Engineering
- Identified the limitation of ET SCAN rules on internal RFC1918 traffic and engineered a custom Suricata rule (SID 9000001) that fires within 5 seconds of scan initiation
- Created 96 Sysmon-based detection rules mapped to MITRE ATT&CK
- Identified a KQL field tokenization issue where `*-enc*` wildcard silently fails on encoded PowerShell detection in this Elastic build, documented and remediated

### Pipeline Engineering
- Identified and resolved a FreeBSD syslogd truncation issue (480-byte hard limit vs 800-1200 byte EVE JSON records) by replacing the UDP syslog pipeline with a standalone Filebeat binary on pfSense, eliminating silent data loss
- Built and validated dual telemetry pipelines: Suricata EVE JSON via Filebeat (NDR) and Sysmon via Elastic Agent (EDR), operating independently with no shared data path

### Investigation Capability
- Executed a connected IR-002 through IR-005 kill chain with Defender ON throughout, all techniques LOLBin-based, no malware required
- Reconstructed the full kill chain in IR-005 using three pivot points: NDR timestamp anchor, ProcessGuid parent-child chain, and cross-layer correlation
- Confirmed that endpoint and network telemetry independently corroborate the same C2 channel: 23 Sysmon EID 3 events and 23 Suricata HTTP flow records, matching source IP, destination IP, and timestamp window, collected by two separate sensors with no shared data path
- Conducted a complete Argus investigation in IR-006 against CASE-011: process tree analysis, cross-layer corroboration of 3x PowerShell HTTP retrievals across independent EDR and NDR pipelines, entity pivot to hunt workbench, and analyst action logging — full workflow validated against live telemetry

### Argus: SOC Investigation Console
- Behavior detector polls Elasticsearch every 60 seconds, maps raw Sysmon EID 1 events to MITRE ATT&CK using 96 custom detection rules, writes structured behavior documents with deterministic IDs to a dedicated index
- Case builder groups behaviors into cases using a 10-minute sliding window, density check, and multi-tactic requirement: prevents noise from generating false cases
- React workstation shell with persistent case queue, canvas-based process tree with zoom, pan, hover path tracing and node click, behavior timeline, detection logic, and raw events tabs
- Claude Haiku integrated at three points: case summaries, per-behavior analyst briefings with next steps, and hunt workbench co-pilot: narration only, never used for scoring or detection
- Hunt workbench with 7 ES|QL templates covering rare parent-child pairs, encoded PowerShell, scheduled task creation, network connections by process, registry persistence, LOLBin execution, and lateral movement patterns
- Full analyst action trail: ESCALATE, BLOCK IP, ADD NOTE all written back to Elasticsearch with timestamps
- Background automation: victim VM runs Atomic Red Team techniques probabilistically every 30 minutes via Task Scheduler, keeping the lab producing telemetry autonomously
- See [ARGUS.md](argus/ARGUS.md) for full documentation and screenshots

---

## Architecture Overview

Traffic between attacker and victim is forced through a monitored pfSense interface, ensuring all attack activity is observable by Suricata regardless of attacker behavior.

- Node 1: SOC Core (Elastic SIEM + Fleet Server)
- Node 2: Proxmox lab (pfSense, Kali attacker, Windows victim)
- pfSense: Routing + Suricata IDS + Filebeat NDR pipeline
- Network segmentation:
  - 10.0.30.0/24: Attack network (Kali)
  - 10.0.20.0/24: Victim network (Windows 10)
- Monitored traffic must traverse pfSense OPT1 (Suricata interface)

---

## Architecture Diagram

![Homelab Architecture](diagrams/homelab-diagram.png)

*Figure: Segmented lab with Suricata positioned on OPT1 to monitor attack traffic between networks*

---

## Architecture Detailed

```
192.168.100.0/24 - HOME LAN
|
+-- Node 1: SOC Core (192.168.100.143)
|   +-- Elasticsearch + Kibana + Fleet Server + Elastic Agent
|
+-- Node 2: Proxmox (192.168.100.2)
    |
    +-- VM 100: pfSense (Router + IDS + NDR Sensor)
    |   +-- WAN  -> 192.168.100.144 (vmbr0)
    |   +-- LAN  -> 10.0.20.1/24   (vmbr1 - Victim Network)
    |   +-- OPT1 -> 10.0.30.1/24   (vmbr2 - Attack Network)
    |        +-- Suricata (monitoring OPT1 / vtnet2)
    |        +-- Filebeat 7.14.0 (EVE JSON -> ES :9200)
    |
    +-- VM 101: Kali Linux
    |   +-- 10.0.30.10 (Attack Network - vmbr2)
    |
    +-- VM 102: Windows 10 Victim (DESKTOP-MM1REM9)
        +-- 10.0.20.10 (Victim Network - vmbr1)
            +-- Sysmon v15.20 + Elastic Agent 8.17.0
```

**Monitored Traffic Path (Suricata visible):**

```
Kali (10.0.30.10)
   -> pfSense OPT1 (Suricata)
   -> pfSense LAN
   -> Victim (10.0.20.10)
```

**Unmonitored Path (Suricata blind spot):**

```
Kali -> Node 1 (192.168.100.143)
```

---

## Detection Pipelines

### Endpoint Pipeline (EDR)

```
Victim (10.0.20.10)
  -> Sysmon v15.20
  -> Elastic Agent 8.17.0
  -> Fleet Server (Node 1 :8221)
  -> Elasticsearch :9200
  -> Kibana (logs-* data view)
```

### Network Pipeline (NDR)

```
Kali (10.0.30.10)
  -> pfSense OPT1 (Suricata)
  -> EVE JSON -> /var/log/suricata/suricata_vtnet242556/eve.json
  -> Filebeat 7.14.0 (standalone binary on pfSense FreeBSD)
  -> Elasticsearch :9200 (HTTP)
  -> Kibana (filebeat-* data view)
```

---

## Detection Engineering

### Custom Suricata Rule (SID 9000001)

Standard ET SCAN rules do not fire on internal RFC1918 traffic. This is a documented Suricata limitation that affects any lab or production environment using private IP ranges. SID 9000001 is a custom rule engineered to close this gap:

```
alert tcp 10.0.30.0/24 any -> 10.0.20.0/24 any (
  msg:"LOCAL SCAN Kali SYN Sweep to Victim";
  flow:stateless; flags:S;
  threshold:type both, track by_src, count 15, seconds 5;
  sid:9000001; rev:1;
)
```

Fires within 5 seconds of Nmap SYN scan initiation. Validated in IR-002.

### Sysmon Detection Rules

- 96 custom KQL-based detection rules
- Coverage across MITRE ATT&CK tactics
- Export: `detection-rules/sysmon-custom-rules.ndjson`

---

## Repository Structure

```
soc-homelab/
+-- README.md
+-- DASHBOARDS.md
+-- diagrams/
|   +-- homelab-diagram.png
+-- docker/
|   +-- elastic/
|       +-- docker-compose.yml
+-- detection-rules/
|   +-- sysmon-custom-rules.ndjson
|   +-- sysmon-custom-rules.ps1
+-- config/
|   +-- sysmon-config.xml
+-- scripts/
|   +-- Create-SysmonDetectionRules.ps1
+-- dashboards/
|   +-- kibana-dashboards.ndjson
+-- argus/
|   +-- ARGUS.md
|   +-- behavior_detector.py
|   +-- case_builder.py
|   +-- process_tree_builder.py
|   +-- hunt_engine.py
|   +-- app.py
|   +-- start_argus.ps1
|   +-- frontend-react/
|   +-- screenshots/
|       +-- Case_Queue_.png
|       +-- Case_selected.png
|       +-- Process_Tree_Full_Chain.png
|       +-- Process_tree.png
|       +-- Timeline.png
|       +-- Hunt_Workbench.png
|       +-- Hunt_Workbench_Claude_Integration.png
+-- investigation-reports/
    +-- dashboards/
    |   +-- screenshots/
    +-- IR-001/
    +-- IR-002/
    +-- IR-003/
    +-- IR-004/
    +-- IR-005/
    +-- IR-006/
        +-- IR-006-argus-detection-powershell-persistence.md
        +-- IR-006-notes.txt
        +-- screenshots/
        +-- raw-events/
```

---

## Stack

| Component | Version | Role |
|---|---|---|
| Elasticsearch | 8.17.0 | Data storage and search |
| Kibana | 8.17.0 | SIEM interface and investigation |
| Elastic Agent | 8.17.0 | EDR collection on victim |
| Sysmon | v15.20 | Endpoint telemetry |
| Suricata | CE (pfSense) | Network IDS |
| Filebeat | 7.14.0 | NDR pipeline (pfSense FreeBSD) |
| pfSense | CE 2.8.1 | Routing and IDS |
| Proxmox | VE | Hypervisor (Node 2) |
| Kali Linux | Latest | Attack platform |
| Python | 3.14 | Argus daemons |
| React 18 + TypeScript | Vite 8 | Argus frontend |
| FastAPI | Latest | Argus API backend |
| Claude Haiku | claude-haiku-4-5 | Argus AI narration layer |

---

## Hardware

| Node | Device | CPU | RAM | Role |
|---|---|---|---|---|
| Node 1 | Dell Inspiron 3593 | i5-1035G1 | 16GB | SOC Core |
| Node 2 | Dell E7250 | i5-5300U | 8GB | Proxmox Lab |

---

## Author

Farrukh Ejaz
GitHub: https://github.com/farrukhCTI
LinkedIn: https://linkedin.com/in/farrukhejazminhas
