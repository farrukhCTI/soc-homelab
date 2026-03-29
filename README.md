# SOC Homelab

A realistic SOC simulation built on constrained consumer hardware to detect attacker activity using Sysmon and Suricata, and analyze it in Elasticsearch/Kibana across two physical nodes.

Focus: detection engineering, alert validation, and multi-source telemetry correlation.

---

## Key Achievements

- Built segmented lab where attack traffic must traverse a monitored interface (Suricata on OPT1)
- Identified limitation of ET SCAN rules in internal traffic scenarios and built a custom rule to close the gap
- Designed and implemented custom Suricata rule (SID 9000001) to detect lateral scanning between attack and victim networks
- Created 95 Sysmon-based detection rules mapped to MITRE ATT&CK across 11 tactic categories
- Verified correlation between network alerts (Suricata EVE JSON) and endpoint telemetry (Sysmon) in Kibana

---

## Architecture

```
192.168.100.0/24 — HOME LAN (Huawei EG8145V5)
│
├── Node 1: SOC Core — Dell Inspiron 3593 | i5-1035G1 | 16GB | Windows 11
│   ├── Elasticsearch 8.17.0        (Docker, port 9200)
│   ├── Kibana 8.17.0               (Docker, port 5601)
│   ├── Elastic Agent 8.17.0        (Fleet Server, port 8221)
│   ├── Sysmon v15.15               (SwiftOnSecurity config)
│   └── 95 Custom Detection Rules   (KQL, all enabled)
│
└── Node 2: Attack Lab — Dell E7250 | i5-5300U | 8GB | Proxmox VE 9.1.6
    │
    ├── VM 100: pfSense CE 2.8.1
    │   ├── WAN   vtnet0   192.168.100.144   (vmbr0)
    │   ├── LAN   vtnet1   10.0.20.1/24      (vmbr1)
    │   ├── OPT1  vtnet2   10.0.30.1/24      (vmbr2)
    │   └── Suricata on OPT1 (vtnet2) — ET Open ruleset
    │
    ├── VM 101: Kali Linux 2025.4
    │   └── vmbr2 — 10.0.30.10  (attack network)
    │
    └── VM 102: Windows 10 Pro 22H2
        ├── vmbr1 — 10.0.20.10  (victim network)
        ├── Sysmon v15.20
        └── Elastic Agent 8.17.0 (enrolled, victim-policy)
```

---

## Detection Pipelines

```
ENDPOINT PIPELINE
Victim (10.0.20.10)
  └── Sysmon v15.20
        └── Elastic Agent 8.17.0
              └── Fleet Server (Node 1 :8221)
                    └── Elasticsearch :9200
                          └── Kibana :5601

NETWORK PIPELINE
Kali (10.0.30.10) ──► pfSense OPT1 (vtnet2) ──► pfSense LAN ──► Victim (10.0.20.10)
                              │
                         Suricata IDS
                         (ET Open rules + custom local rules)
                              │
                         EVE JSON via UDP syslog :514
                              │
                         Elastic Agent (Node 1)
                              │
                         Elasticsearch :9200
                              └── Kibana :5601
```

Both pipelines verified end-to-end. Suricata EVE alerts and Sysmon Process Create events confirmed live in Kibana.

---

## Detection Engineering

### Custom Suricata Rule

ET SCAN rules do not fire on internal traffic. This rule was built to close that gap.

Kali and the victim both sit in HOME_NET, so ET rules requiring EXTERNAL_NET as source will never match. A custom local rule handles detection directly:

```
alert tcp 10.0.30.0/24 any -> 10.0.20.0/24 any (
  msg:"LOCAL SCAN Kali SYN Sweep to Victim";
  flow:stateless; flags:S;
  threshold:type both, track by_src, count 15, seconds 5;
  sid:9000001; rev:1;
)
```

Fires within 5 seconds of `nmap -Pn -sS`. Alert confirmed arriving in Kibana via `data_stream.dataset: udp.generic`.

### Custom KQL Detection Rules (95 total)

All rules target the `logs-*` index. Written as KQL custom query rules. Fully simulatable without paid EDR.

| Category | Rules | MITRE Tactics |
|---|---|---|
| PowerShell Abuse | 4 | T1059.001 |
| CMD + LOLBins | 10 | T1059.003, T1218 |
| Persistence | 6 | T1543.003, T1547.001, T1053.005 |
| Privilege Escalation | 4 | T1055, T1548 |
| Credential Access | 5 | T1003, T1110 |
| Defense Evasion | 8 | T1562, T1036, T1027 |
| Discovery | 10 | T1087, T1082, T1016, T1049 |
| Lateral Movement | 4 | T1021 |
| Command and Control | 6 | T1071, T1090 |
| Impact / Ransomware | 3 | T1490 |
| Collection | 3 | T1560, T1115, T1056 |
| Suricata Network | 5 | Multiple |
| **Total** | **95** | |

Rules exported to `detection-rules/sysmon-custom-rules.ndjson`. Import directly into any Elastic 8.x instance via Kibana Security > Rules > Import.

---

## Build Status

### Phase 0: Node 1 baseline — COMPLETE
- Elasticsearch, Kibana, Fleet Server running in Docker
- Sysmon with SwiftOnSecurity config installed
- 95 custom detection rules imported and enabled
- ILM policies configured

### Phase 1: Proxmox network foundation — COMPLETE
- Proxmox VE 9.1.6 on Node 2
- vmbr0 (WAN), vmbr1 (LAN, no host IP), vmbr2 (OPT1, no host IP)
- Hardware offloading disabled

### Phase 2: pfSense — COMPLETE
- WAN / LAN / OPT1 interfaces configured
- DHCP on LAN (10.0.20.10-100) and OPT1 (10.0.30.10-100)
- NAT Outbound Hybrid mode
- Disable reply-to enabled
- SSH accessible

### Phase 3: Suricata — COMPLETE
- Installed on pfSense, watching OPT1 (vtnet2)
- ET Open rules enabled (emerging-scan, emerging-exploit)
- EVE JSON output via syslog to Node 1 :514
- Custom local rule SID 9000001 confirmed firing

### Phase 4: Suricata logs to Elastic — COMPLETE
- UDP Logs integration in Fleet Server Policy (0.0.0.0:514)
- pfSense remote syslog wired to Node 1 :514
- EVE JSON alerts confirmed in Kibana (data_stream.dataset: udp.generic)

### Phase 5: Windows 10 Victim VM — COMPLETE
- VM 102, vmbr1, IP 10.0.20.10
- Sysmon v15.20 installed
- Elastic Agent 8.17.0 enrolled, status Healthy
- 5,100+ Sysmon events confirmed in Kibana
- Snapshot: victim-clean-baseline

### Phase 6: End-to-end audit — COMPLETE
- Both detection pipelines verified simultaneously
- Kali nmap triggers SID 9000001, alert reaches Kibana
- Sysmon Process Create events flowing in real time

### Phase 7: Detection rules import — COMPLETE
- 95 rules imported via Kibana Security > Rules > Import
- All rules enabled, all showing Succeeded

### Phase 8: Attack simulation and IR reports — IN PROGRESS
- IR-001: COMPLETE (Ingress tool transfer and scheduled task persistence)
- IR-002 through IR-005: NOT STARTED

---

## Repository Structure

```
soc-homelab/
├── README.md
├── .gitignore
├── docker/
│   └── elastic/
│       ├── docker-compose.yml
│       └── .env.example
├── detection-rules/
│   ├── sysmon-custom-rules.ndjson      # 95 custom detection rules (importable)
│   └── sysmon-custom-rules.ps1         # PowerShell bulk rule creation script
├── config/
│   └── sysmon-config.xml               # SwiftOnSecurity Sysmon config
├── scripts/
│   └── Create-SysmonDetectionRules.ps1
└── └── investigation-reports/
    ├── IR-001.md
    ├── IR-002.md
    ├── IR-003.md
    ├── IR-004.md
    ├── IR-005.md
    └── screenshots/
        └── IR-001/
            ├── kibana-event1-schtasks.png
            ├── kibana-event3-certutil-network.png
            └── kibana-event11-task-file.png
```

---

## Stack

| Component | Version | Role |
|---|---|---|
| Elasticsearch | 8.17.0 | Data store and search engine |
| Kibana | 8.17.0 | SIEM UI, dashboards, detection rules |
| Elastic Agent (SOC) | 8.17.0 | Fleet Server + endpoint telemetry |
| Elastic Agent (Victim) | 8.17.0 | Endpoint telemetry |
| Sysmon (SOC node) | v15.15 | Windows endpoint telemetry |
| Sysmon (Victim) | v15.20 | Windows endpoint telemetry |
| Suricata | pfSense pkg | Network IDS on OPT1 (vtnet2) |
| pfSense | CE 2.8.1 | Firewall and network segmentation |
| Proxmox VE | 9.1.6 | Hypervisor |
| Kali Linux | 2025.4 | Attack simulation |

---

## Hardware

| Node | Device | CPU | RAM | Role |
|---|---|---|---|---|
| Node 1 | Dell Inspiron 3593 | i5-1035G1 (4c/8t) | 16GB DDR4 | SOC Core (Windows 11) |
| Node 2 | Dell E7250 | i5-5300U (2c/4t) | 8GB | Proxmox Host |
| Router | Huawei EG8145V5 | — | — | 192.168.100.0/24 gateway |

---

## Author

Farrukh Ejaz

- GitHub: [farrukhCTI](https://github.com/farrukhCTI)
- LinkedIn: [farrukhejazminhas](https://linkedin.com/in/farrukhejazminhas)
- Repository: [farrukhCTI/soc-homelab](https://github.com/farrukhCTI/soc-homelab)
