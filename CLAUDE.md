# SOC Homelab - Session Context
Last updated: 2026-03-20 (Friday, ~10:30 PKT)

---

## Project Goal
Building SOC + CTI homelab targeting Pakistan SOC market (IT Butler Islamabad primary target, SOC Analyst L1).
GitHub: https://github.com/farrukhCTI/soc-homelab

---

## Hardware

### Node 1: Windows Dell Inspiron 3593 (SOC Core)
- CPU: i5-1035G1 (4c/8t)
- RAM: 16GB DDR4
- Storage: WD 1TB HDD (E:\ project) + ADATA 238GB NVMe (C:\)
- NIC ethernet MAC: 98:E7:43:2E:73:AB
- OS: Windows 11 Pro
- Project path: E:\soc-homelab
- IP: 192.168.100.143 (DHCP locked)

### Node 2: Dell E7250 (Proxmox Host)
- CPU: i5-5300U (2c/4t)
- RAM: 8GB
- OS: Proxmox VE 9.1.6 (Debian Trixie)
- IP: 192.168.100.2 (DHCP locked)
- Proxmox web UI: https://192.168.100.2:8006
- Lid close: ignored, running headlessly on UPS socket

---

## Router
- Model: Huawei EG8145V5
- Admin: http://192.168.100.1 (telecomadmin / admintelecom)
- Subnet: 192.168.100.0/24

### DHCP Reservations
| MAC | IP | Device |
|---|---|---|
| 34:E6:D7:88:7D:B0 | 192.168.100.2 | Proxmox |
| 98:E7:43:2E:73:AB | 192.168.100.143 | Windows Dell |
| BC:24:11:6A:13:C2 | 192.168.100.144 | pfSense WAN |

---

## Credentials (KEEP LOCAL, NEVER PUSH TO GITHUB)
| Service | User | Password |
|---|---|---|
| Proxmox | root | 92707927 |
| pfSense web UI | admin | 92707927 |
| Suricata-Zeek LXC SSH | root | 92707927 |
| Elasticsearch | elastic | SOCHomelab2026! |
| Kibana system | kibana_system | SOCHomelab2026! |

---

## Node 1: PARTIALLY COMPLETE

### Running
- Docker Desktop v29.2.1 (WSL2, 10GB cap)
- Elasticsearch 8.17.0 + Kibana 8.17.0 in Docker
- Sysmon v15.15 with SwiftOnSecurity config (installed, NOT yet shipping to Elastic)
- Docker compose: E:\soc-homelab\docker\elastic\docker-compose.yml

### Start Node 1 after reboot
```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
cd E:\soc-homelab
docker compose -f docker/elastic/docker-compose.yml up -d
```

### Pending
- Elastic Agent install + Fleet enrollment (NEXT IMMEDIATE TASK)
- Sysmon logs into Elastic SIEM
- Prebuilt Windows detection rules
- TheHive + Cortex in Docker
- Shuffle SOAR in Docker
- MISP in Docker
- Custom MITRE ATT&CK detection rules

---

## Node 2: PHASE 1 COMPLETE

### VM 100: pfSense CE 2.8.1
- Status: RUNNING
- RAM: 1024MB, Disk: 16GB
- WAN: 192.168.100.144 (vmbr0), LAN: 10.0.20.1/24 (vmbr1)
- Web UI: http://192.168.100.144
- DNS: 8.8.8.8 / 8.8.4.4, Timezone: Asia/Karachi

### CT 101: suricata-zeek (Debian 12, privileged)
- Status: RUNNING
- IP: 192.168.100.145
- SSH: ssh root@192.168.100.145
- eth0: management, eth1: promiscuous sniffing (no IP)

#### Suricata 6.0.10
- Interface: eth1, ET Open rules (49,083)
- EVE JSON: /var/log/suricata/eve.json
- community-id: enabled
- Service: enabled + running

#### Zeek 8.1.1
- Interface: eth1, standalone mode
- Logs: /opt/zeek/logs/current/
- PATH: /opt/zeek/bin in /etc/profile
- Service: zeekctl deploy

#### Filebeat 8.17.0
- Modules: suricata + zeek enabled
- Output: Elasticsearch at 192.168.100.143:9200
- Kibana: 192.168.100.143:5601
- Dashboards loaded: [Filebeat Suricata] Alert Overview + Events Overview
- Status: 26,864+ documents in Elasticsearch, actively shipping
- Service: enabled + running

---

## Full Pipeline Status
```
Network traffic
  > eth1 promiscuous
  > Suricata (49,083 ET rules) + Zeek (behavioural)
  > EVE JSON + Zeek logs
  > Filebeat
  > Elasticsearch 8.17 (Windows Dell Docker)
  > Kibana dashboards [LIVE]

Sysmon (Windows Dell) [PENDING - NEXT]
  > Elastic Agent + Fleet
  > Elasticsearch
  > Kibana
```

---

## Key URLs
| Service | URL |
|---|---|
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |
| Router | http://192.168.100.1 |
| Proxmox | https://192.168.100.2:8006 |
| pfSense | http://192.168.100.144 |
| Suricata-Zeek SSH | ssh root@192.168.100.145 |

---

## Remaining Build Plan

### Phase 2: Endpoint Detection (START HERE)
1. Install Elastic Agent on Windows Dell via Fleet in Kibana
2. Enable Sysmon integration in Fleet policy
3. Verify Sysmon events (process creation, network, registry) in Kibana
4. Enable prebuilt Windows detection rules in Kibana Security

### Phase 3: Detection Engineering
5. Write 4 custom MITRE ATT&CK rules (T1059.001, T1110, T1543.003, T1071)
6. Deploy Kali Linux VM on Proxmox
7. Windows 10 victim VM with Sysmon
8. Run attack simulations, verify detections fire end to end

### Phase 4: Case Management + Automation
9. TheHive + Cortex in Docker on Windows Dell
10. Shuffle SOAR in Docker
11. Wire: Elastic alert > Shuffle > VirusTotal > TheHive
12. MISP for threat intel

### Phase 5: Polish
13. Nginx Proxy Manager LXC (clean URLs)
14. Tailscale LXC (remote access)
15. Suricata rule tuning
16. ILM policies in Elasticsearch

### Phase 6: Claude API Tooling
17. ai_triage.py, ai_report_generator.py, ai_detection_advisor.py

---

## Important Notes
- docker-compose.yml uses .env file for passwords, .env is gitignored
- git filter-repo was used to clean password history, force pushed clean
- Proxmox subscription nag removed
- pfSense WAN memory: 1024MB (FreeBSD reports inflated usage in Proxmox, actual is ~26%)
- eth1 on suricata-zeek LXC must be brought up manually if LXC reboots (configured in /etc/network/interfaces)
- Zeek PATH must be sourced: source /etc/profile or log out/in after LXC reboot

---

## How to Start Next Session
Paste this file and say:
"Continuing SOC homelab build. Everything is running. Next task is Elastic Agent + Fleet setup on Windows Dell. Kibana is at http://localhost:5601."

### ILM Policies (COMPLETE)
- homelab-network-logs: hot 5GB/7d, delete 14d (attached to filebeat-8.17.0)
- homelab-endpoint-logs: hot 3GB/3d, delete 7d (ready for Elastic Agent endpoint data)