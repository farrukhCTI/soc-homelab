# SOC Homelab

A production-grade Security Operations Center homelab built on constrained consumer hardware, targeting Pakistan SOC market roles. Designed to demonstrate end-to-end detection engineering, threat hunting, and incident response capabilities.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Node 1: SOC Core                        │
│              Dell Inspiron i5-1035G1 | 16GB | Windows 11        │
│                                                                  │
│  ┌─────────────────┐   ┌─────────────┐   ┌──────────────────┐  │
│  │  Elasticsearch  │   │   Kibana    │   │  Elastic Agent   │  │
│  │    8.17.0       │◄──│   8.17.0    │   │  Fleet Server    │  │
│  │   port 9200     │   │  port 5601  │   │  port 8221       │  │
│  └────────┬────────┘   └─────────────┘   └────────┬─────────┘  │
│           │                                        │             │
│           │◄───────────────────────────────────────┘             │
│           │              Sysmon v15.15                           │
│           │         SwiftOnSecurity config                       │
└───────────┼─────────────────────────────────────────────────────┘
            │
            │ Elasticsearch API (9200)
            │
┌───────────┼─────────────────────────────────────────────────────┐
│           │              Node 2: Proxmox Host                   │
│           │         Dell E7250 i5-5300U | 8GB | Proxmox 9.1    │
│           │                                                      │
│  ┌────────┴────────┐   ┌─────────────────────────────────────┐  │
│  │    Filebeat     │   │         VM 100: pfSense CE          │  │
│  │    8.17.0       │   │    WAN: 192.168.100.144 (vmbr0)     │  │
│  │  Suricata +     │   │    LAN: 10.0.20.1/24    (vmbr1)     │  │
│  │  Zeek modules   │   └─────────────────────────────────────┘  │
│  └────────┬────────┘                                             │
│           │              CT 101: suricata-zeek LXC              │
│  ┌────────┴────────┐   ┌─────────────────────────────────────┐  │
│  │   Suricata      │   │  eth0: management (192.168.100.145) │  │
│  │   6.0.10        │   │  eth1: promiscuous sniffing (no IP)  │  │
│  │   ET Open rules │   └─────────────────────────────────────┘  │
│  │   49,083 sigs   │                                             │
│  └─────────────────┘                                             │
│  ┌─────────────────┐                                             │
│  │   Zeek 8.1.1    │                                             │
│  │   standalone    │                                             │
│  └─────────────────┘                                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Live Data Pipelines

```
# Endpoint Pipeline
Sysmon (Windows) → Elastic Agent (Fleet) → Elasticsearch → Kibana [LIVE]

# Network Pipeline
Network Traffic → eth1 promiscuous → Suricata + Zeek → Filebeat → Elasticsearch → Kibana [LIVE]
```

---

## Stack

| Component | Version | Role |
|---|---|---|
| Elasticsearch | 8.17.0 | Data store and search engine |
| Kibana | 8.17.0 | SIEM UI, dashboards, detection rules |
| Elastic Agent | 8.17.0 | Fleet Server + endpoint telemetry |
| Sysmon | v15.15 | Windows endpoint telemetry |
| Suricata | 6.0.10 | Network IDS (49,083 ET Open rules) |
| Zeek | 8.1.1 | Network traffic analysis |
| Filebeat | 8.17.0 | Log shipper (Suricata + Zeek modules) |
| pfSense | CE 2.8.1 | Firewall and network segmentation |
| Proxmox VE | 9.1.6 | Hypervisor for attack lab VMs |

**Planned (Phase 4+):**
- TheHive 5 + Cortex (case management + enrichment)
- Shuffle SOAR (alert orchestration)
- MISP (threat intelligence platform)
- Claude API (AI-assisted triage tooling)

---

## Detection Engineering

### Custom Rules (96 total)
All rules target `logs-*` index with `event.dataset: windows.sysmon_operational`, Suricata, and Zeek data sources. Written as KQL custom query rules, fully simulatable without paid EDR.

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
| Zeek Network | 4 | Multiple |

Rules are exported to `detection-rules/sysmon-custom-rules.ndjson` and can be imported directly into any Elastic 8.x instance.

---

## Build Status

### Phase 1: Network Detection [COMPLETE]
- [x] Proxmox VE installed on Node 2
- [x] pfSense CE deployed (WAN/LAN segmentation)
- [x] Suricata LXC with ET Open ruleset (49,083 signatures)
- [x] Zeek LXC in standalone mode
- [x] Filebeat shipping Suricata + Zeek logs to Elasticsearch
- [x] ILM policies configured (network: 14d, endpoint: 7d)

### Phase 2: Endpoint Detection [COMPLETE]
- [x] Elasticsearch + Kibana 8.17.0 in Docker
- [x] Sysmon v15.15 with SwiftOnSecurity config
- [x] Elastic Agent installed natively as Fleet Server (port 8221)
- [x] Windows integration with Sysmon Operational channel enabled
- [x] 96 custom detection rules created and enabled
- [x] End-to-end alert pipeline verified

### Phase 3: Attack Simulation [IN PROGRESS]
- [ ] Kali Linux VM on Proxmox
- [ ] Windows 10 victim VM with Sysmon
- [ ] Attack simulations mapped to MITRE ATT&CK
- [ ] Alert triage documented

### Phase 4: Case Management + Automation
- [ ] TheHive 5 + Cortex in Docker
- [ ] Shuffle SOAR in Docker
- [ ] Wire: Elastic alert > Shuffle > VirusTotal > TheHive
- [ ] MISP threat intel integration

### Phase 5: Polish
- [ ] Nginx Proxy Manager LXC
- [ ] Tailscale remote access
- [ ] Suricata rule tuning

### Phase 6: Claude API Tooling
- [ ] ai_triage.py
- [ ] ai_report_generator.py
- [ ] ai_detection_advisor.py

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
│   └── sysmon-custom-rules.ndjson   # 96 custom Sysmon detection rules
├── scripts/
│   └── Create-SysmonDetectionRules.ps1
├── config/
│   └── sysmon-config.xml            # SwiftOnSecurity Sysmon config
└── docs/
    └── architecture.md
```

---

## Hardware

| Node | Device | CPU | RAM | Role |
|---|---|---|---|---|
| Node 1 | Dell Inspiron 3593 | i5-1035G1 (4c/8t) | 16GB DDR4 | SOC Core (Windows 11) |
| Node 2 | Dell E7250 | i5-5300U (2c/4t) | 8GB | Proxmox Host |
| Router | Huawei EG8145V5 | - | - | 192.168.100.0/24 |

---

## Author

**Farrukh Ejaz Minhas**
CTI analyst transitioning into SOC operations | Rawalpindi, Pakistan
- GitHub: [farrukhCTI](https://github.com/farrukhCTI)
- LinkedIn: [farrukhejazminhas](https://linkedin.com/in/farrukhejazminhas)
- Certifications: ArcX CTI 101 | ISC2 CC (in progress)
- Background: 9 years aviation flight operations (Qatar Airways, Gulf Air, Airblue)
