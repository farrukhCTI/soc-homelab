# SOC Homelab: Detection & Incident Response

**Focus:** SOC Analyst | Detection Engineering | Incident Response

This lab demonstrates how a single network alert can be expanded into a full kill chain investigation using endpoint telemetry and cross-layer correlation.

---

## How to Review This Project

1. Start with **IR-005**: full kill chain reconstruction from a single NDR alert anchor
2. Refer to **IR-002 through IR-004** for individual attack stages
3. Use screenshots and raw events in each report folder for validation

---

## What this demonstrates

- Correlated independent NDR and EDR telemetry to validate C2 activity across both network and endpoint layers
- Reconstructed a full attack kill chain from a single Suricata alert using ProcessGuid chaining and timestamp pivoting
- Engineered custom detection rules where standard tooling had documented blind spots
- Incident response investigations mapped to MITRE ATT&CK with detection gap analysis and remediation design
- Pipeline engineering to solve real infrastructure limitations, not just configure existing tools

---

## Investigation Reports

All five investigations cover a connected kill chain simulating LOLBin-based pre-ransomware operator behavior on a defended Windows 10 endpoint (Defender ON, UAC ON throughout).

| Report | Title | MITRE TTPs | Status |
|---|---|---|---|
| IR-001 | Tool Transfer and Persistence | T1105, T1053.005, T1218.003 | Complete |
| IR-002 | Reconnaissance and Host Discovery | T1046, T1082, T1033, T1016 | Complete |
| IR-003 | Encoded PowerShell Execution and C2 Beaconing | T1059.001, T1027, T1071.001, T1105 | Complete |
| IR-004 | Defense Evasion and Persistence | T1218.005, T1547.001, T1562.001, T1036 | Complete |
| IR-005 | Correlated Kill Chain Hunt | Cross-layer, all TTPs | Complete |

IR-005 is the portfolio centrepiece: a pure analyst exercise reconstructing the full kill chain from a single NDR alert by pivoting on timestamp, chaining ProcessGuid relationships, and validating activity independently across both EDR and NDR datasets.

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

---

## Architecture (Overview)

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

## Architecture (Detailed)

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
+-- investigation-reports/
    +-- IR-001/
    |   +-- IR-001-tool-transfer-and-persistence.md
    |   +-- screenshots/
    +-- IR-002/
    |   +-- IR-002-reconnaissance-and-host-discovery.md
    |   +-- screenshots/
    |   +-- raw-events/
    +-- IR-003/
    |   +-- IR-003-encoded-execution-and-c2-beaconing.md
    |   +-- screenshots/
    |   +-- raw-events/
    +-- IR-004/
    |   +-- IR-004-defense-evasion-and-persistence.md
    |   +-- screenshots/
    |   +-- raw-events/
    +-- IR-005/
        +-- IR-005-correlated-kill-chain-hunt.md
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
