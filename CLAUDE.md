# SOC Homelab - Session Context
Last updated: 2026-03-20 (Friday, ~07:30 PKT)

---

## Project Goal
Building SOC + CTI homelab targeting IT Butler Islamabad (SOC Analyst L1, requires Elastic SIEM) and Pakistan SOC market.
GitHub: https://github.com/farrukhCTI/soc-homelab

---

## Hardware

### Node 1: Windows Dell Inspiron 3593 (SOC Core)
- CPU: i5-1035G1 (4c/8t, turbo 3.6GHz, Ice Lake 10nm)
- RAM: 16GB DDR4 dual channel
- Storage: WD 1TB HDD (E:\ project) + ADATA SX6000PNP 238GB NVMe (C:\)
- NIC: Realtek RTL8136 ethernet MAC: 98:E7:43:2E:73:AB
- OS: Windows 11 Pro Build 26200.7922
- Project path: E:\soc-homelab
- IP: 192.168.100.143 (DHCP reservation locked)

### Node 2: Dell E7250 (Proxmox Host)
- CPU: i5-5300U (2c/4t)
- RAM: 8GB
- OS: Proxmox VE 9.1.6 (Debian Trixie, kernel 6.17.2-1-pve)
- IP: 192.168.100.2 (DHCP reservation locked)
- MAC (ethernet nic0): 34:E6:D7:88:7D:B0
- Proxmox web UI: https://192.168.100.2:8006
- Lid close: ignore (headless, on UPS socket)
- Status: ACTIVE

---

## Router
- Model: Huawei EG8145V5
- Admin panel: http://192.168.100.1
- Login: telecomadmin / admintelecom
- Subnet: 192.168.100.0/24
- Gateway: 192.168.100.1

### DHCP Reservations (ALL CONFIGURED)
| MAC | IP | Description |
|---|---|---|
| 34:E6:D7:88:7D:B0 | 192.168.100.2 | Proxmox-E7250 |
| 98:E7:43:2E:73:AB | 192.168.100.143 | SOC-Core-Windows |
| BC:24:11:6A:13:C2 | 192.168.100.144 | pfSense-WAN |

---

## Node 1 Status: PARTIALLY COMPLETE

### Completed
- Git, Docker Desktop v29.2.1, WSL2 (10GB cap)
- Sysmon v15.15 with SwiftOnSecurity config
- Elasticsearch 8.17.0 + Kibana 8.17.0 running in Docker
- GitHub repo: https://github.com/farrukhCTI/soc-homelab
- Docker compose: E:\soc-homelab\docker\elastic\docker-compose.yml
- kibana_system password set
- Kibana accessible and showing Suricata data from Node 2

### Known Issues on Node 1
- vm.max_map_count resets on reboot. Fix:
```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```
- Docker containers must be started manually after reboot:
```powershell
cd E:\soc-homelab
docker compose -f docker/elastic/docker-compose.yml up -d
```

### Pending on Node 1
- Install Elastic Agent, enroll with Fleet (NEXT)
- Sysmon log ingestion into Elastic SIEM
- Enable prebuilt detection rules (Windows category)
- Build first Kibana security dashboard
- Custom MITRE ATT&CK detection rules
- TheHive + Cortex in Docker
- Shuffle SOAR in Docker
- MISP in Docker
- Wire automation: Elastic > Shuffle > VirusTotal > TheHive
- QRadar CE via VirtualBox (on-demand)

---

## Node 2 Status: PHASE 1 COMPLETE

### Proxmox Configuration: COMPLETE
- Proxmox VE 9.1.6, enterprise repos disabled, no-subscription repo active
- vmbr0: physical bridge, nic0, IP 192.168.100.2/24
- vmbr1: internal LAN bridge, no physical port
- Lid close ignored, running headlessly on UPS socket
- Subscription nag removed

### VMs and Containers

#### VM 100: pfSense CE 2.8.1 - COMPLETE
- Status: RUNNING
- CPU: 2 cores, RAM: 1024MB, Disk: 16GB
- WAN: vtnet0 on vmbr0, IP 192.168.100.144, MAC BC:24:11:6A:13:C2
- LAN: vtnet1 on vmbr1, IP 10.0.20.1/24, MAC BC:24:11:D7:00:F9
- Web UI: http://192.168.100.144
- DNS: 8.8.8.8, 8.8.4.4, Timezone: Asia/Karachi
- Hostname: pfsense.lab.local
- LAN DHCP pool: 10.0.20.100 - 10.0.20.200
- Firewall rule: WAN pass from 192.168.100.0/24 to WAN port 80

#### CT 101: suricata-zeek - COMPLETE
- Status: RUNNING
- OS: Debian 12 (privileged container)
- CPU: 2 cores, RAM: 2048MB, Swap: 512MB, Disk: 8GB
- eth0: vmbr0, IP 192.168.100.145/24 (management)
- eth1: vmbr0, NO IP (promiscuous sniffing)
- SSH: root@192.168.100.145 (password in private context)
- LXC config: lxc.cap.drop:, lxc.cgroup2.devices.allow: a, lxc.mount.auto: proc:rw sys:rw, features: nesting=1
- /etc/network/interfaces: eth1 configured as manual, brought up on boot

##### Suricata: COMPLETE
- Version: 6.0.10
- Interface: eth1 (promiscuous)
- Rules: ET Open ruleset, 49083 rules at /var/lib/suricata/rules/
- EVE JSON: /var/log/suricata/eve.json
- community-id: enabled
- Service: enabled, running since 2026-03-18

##### Zeek: COMPLETE
- Version: 8.1.1
- Interface: eth1
- Logs: /opt/zeek/logs/current/
- Service: zeekctl deploy, standalone mode
- PATH: /opt/zeek/bin added to /etc/profile
- websockets: installed (pip3)

##### Filebeat: COMPLETE
- Version: 8.17.0 (matches Elasticsearch)
- Modules enabled: suricata, zeek
- Output: Elasticsearch at 192.168.100.143:9200
- Kibana: 192.168.100.143:5601
- Dashboards loaded: [Filebeat Suricata] Alert Overview, [Filebeat Suricata] Events Overview
- Data flowing: 26,864+ documents in Elasticsearch
- Service: enabled, running

### Planned VMs/LXCs (remaining)
- Nginx Proxy Manager LXC (256MB): clean URLs, use community helper script
- Tailscale LXC (128MB): ZTNA remote access
- Kali Linux VM (2GB, on-demand): attack simulations
- Windows 10 VM: victim endpoint + future honeypot

---

## Full Pipeline Status
```
Network traffic
    > eth1 on suricata-zeek LXC
    > Suricata (signature detection) + Zeek (behavioural analysis)
    > EVE JSON + conn.log/dns.log/http.log etc
    > Filebeat
    > Elasticsearch 8.17.0 (Windows Dell Docker)
    > Kibana dashboards [LIVE]

Sysmon (Windows Dell endpoint) [PENDING - NEXT]
    > Elastic Agent
    > Elasticsearch
    > Kibana
```

---

## Full Target Architecture
```
WINDOWS DELL (SOC Core) - 192.168.100.143
├── Sysmon v15.15 (installed, not yet shipping to Elastic)
├── Docker: Elastic SIEM 8.17 (ES + Kibana) [RUNNING]
├── Docker: TheHive + Cortex [planned]
├── Docker: Shuffle SOAR [planned]
├── Docker: MISP [planned]
└── VirtualBox: QRadar CE [planned, on-demand]

DELL E7250 (Proxmox) - 192.168.100.2
├── VM 100: pfSense CE 2.8.1 [RUNNING]
├── CT 101: suricata-zeek [RUNNING]
│   ├── Suricata IDS [ACTIVE, shipping to Elastic]
│   ├── Zeek NSM [ACTIVE, shipping to Elastic]
│   └── Filebeat 8.17 [ACTIVE]
├── Nginx Proxy Manager LXC [NEXT SESSION]
├── Tailscale LXC [planned]
├── Kali Linux VM [planned]
└── Windows 10 VM [planned]
```

---

## Build Phases

### Phase 1: Node 2 Foundation - COMPLETE
- [x] Proxmox installed and configured
- [x] pfSense VM running
- [x] Suricata LXC with ET Open rules
- [x] Zeek installed and running
- [x] Filebeat shipping to Elastic
- [x] Kibana dashboards live with real data

### Phase 2: Node 1 SIEM - IN PROGRESS
- [ ] Elastic Agent install + Fleet enrollment (NEXT)
- [ ] Sysmon logs into Elastic
- [ ] Suricata + Zeek already flowing
- [ ] Prebuilt detection rules enabled
- [ ] First unified Kibana dashboard

### Phase 3: Detection Engineering
- [ ] Custom MITRE ATT&CK rules (T1059.001, T1110, T1543.003, T1071)
- [ ] Kali VM deployed
- [ ] Attack simulations + detection verification

### Phase 4: Case Management + Automation
- [ ] TheHive + Cortex
- [ ] Shuffle SOAR
- [ ] MISP
- [ ] Full automation pipeline

### Phase 5: Advanced
- [ ] Windows 10 victim VM + honeypot
- [ ] QRadar CE
- [ ] Claude API triage tooling
- [ ] Nginx Proxy Manager (clean URLs)
- [ ] Tailscale (remote access)

---

## Key URLs
| Service | URL |
|---|---|
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |
| Router | http://192.168.100.1 |
| Proxmox | https://192.168.100.2:8006 |
| pfSense | http://192.168.100.144 |
| Suricata-Zeek LXC SSH | ssh root@192.168.100.145 |

---

## Next Session Checklist
1. Start Docker on Windows Dell:
   ```powershell
   wsl -d docker-desktop sysctl -w vm.max_map_count=262144
   cd E:\soc-homelab
   docker compose -f docker/elastic/docker-compose.yml up -d
   ```
2. Install Elastic Agent on Windows Dell
3. Enroll with Fleet in Kibana
4. Configure Sysmon integration
5. Verify Sysmon events in Kibana
6. Enable prebuilt Windows detection rules

---

## Session Continuity
Paste this file at the start of each new session.
Keep passwords in local copy only, never push to GitHub.
