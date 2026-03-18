# SOC Homelab - Session Context
Last updated: 2026-03-19 (Thursday, ~00:30 PKT)

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
- NIC: Realtek RTL8136 ethernet MAC: 98:E7:43:2E:73:AB + Qualcomm QCA9377 WiFi
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
- Lid close: ignore (HandleLidSwitch=ignore, HandleLidSwitchExternalPower=ignore)
- Status: ACTIVE, running headlessly on UPS socket

---

## Router
- Model: Huawei EG8145V5
- Admin panel: http://192.168.100.1
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

### Known Issues on Node 1
- kibana_system password unresolved (PowerShell JSON escaping). Fix:
```powershell
$body = '{"password":"<YOUR_PASSWORD>"}'
$body | Out-File -FilePath "$env:TEMP\es_body.json" -Encoding utf8 -NoNewline
curl.exe -s -u "elastic:<YOUR_PASSWORD>" -X POST "http://localhost:9200/_security/user/kibana_system/_password" -H "Content-Type: application/json" --data-binary "@$env:TEMP\es_body.json"
```
- vm.max_map_count resets on reboot. Fix:
```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

### Pending on Node 1
- Fix kibana_system password
- Install Elastic Agent, enroll with Fleet
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

## Node 2 Status: IN PROGRESS

### Proxmox Configuration: COMPLETE
- Enterprise repos disabled, no-subscription repo active
- Full system updated
- vmbr0: physical bridge, nic0, IP 192.168.100.2/24
- vmbr1: internal LAN bridge, no physical port
- Lid close ignored, running headlessly

### /etc/network/interfaces
```
auto lo
iface lo inet loopback

iface nic0 inet manual

auto vmbr0
iface vmbr0 inet static
        address 192.168.100.2/24
        gateway 192.168.100.1
        bridge-ports nic0
        bridge-stp off
        bridge-fd 0

iface nic0 inet manual

source /etc/network/interfaces.d/*
```

---

## VMs and Containers

### VM 100: pfSense CE 2.8.1 - COMPLETE
- Status: RUNNING
- CPU: 2 cores, RAM: 512MB, Disk: 16GB virtio0
- WAN: vtnet0 on vmbr0, IP 192.168.100.144, MAC BC:24:11:6A:13:C2
- LAN: vtnet1 on vmbr1, IP 10.0.20.1/24, MAC BC:24:11:D7:00:F9
- Web UI: http://192.168.100.144
- DNS: 8.8.8.8, 8.8.4.4
- Timezone: Asia/Karachi
- Hostname: pfsense.lab.local
- LAN DHCP pool: 10.0.20.100 - 10.0.20.200
- Firewall rule: WAN pass from 192.168.100.0/24 to WAN port 80

### CT 101: suricata-zeek - IN PROGRESS
- Status: RUNNING
- OS: Debian 12 (privileged container)
- CPU: 2 cores, RAM: 2048MB, Swap: 512MB, Disk: 8GB
- eth0: vmbr0, IP 192.168.100.145/24 (management)
- eth1: vmbr0, NO IP (promiscuous sniffing interface)
- Firewall: OFF on both interfaces
- LXC config extras:
  - lxc.cap.drop: (empty)
  - lxc.cgroup2.devices.allow: a
  - lxc.mount.auto: proc:rw sys:rw
  - features: nesting=1

#### Suricata Status: CONFIGURED, needs start verification
- Installed: suricata, suricata-update, jq
- Rules: ET Open ruleset (49083 rules) at /var/lib/suricata/rules/
- Config: /etc/suricata/suricata.yaml
- Changes: community-id=true, interfaces=eth1, rules path fixed
- Config test: PASSED (49088 signatures, no errors)
- Service: enabled

#### Zeek Status: NOT YET INSTALLED

### Planned VMs/LXCs
- Nginx Proxy Manager LXC (256MB)
- Tailscale LXC (128MB)
- Kali Linux VM (2GB, on-demand)
- Windows 10 VM (victim endpoint + future honeypot)

---

## Full Target Architecture
```
WINDOWS DELL (SOC Core) - 192.168.100.143
├── Sysmon + Elastic Agent (EDR)
├── Docker: Elastic SIEM 8.17 (ES + Kibana + Fleet)
├── Docker: TheHive + Cortex [planned]
├── Docker: Shuffle SOAR [planned]
├── Docker: MISP [planned]
└── VirtualBox: QRadar CE [planned, on-demand]

DELL E7250 (Proxmox) - 192.168.100.2
├── VM 100: pfSense CE 2.8.1 [RUNNING]
│   ├── WAN: 192.168.100.144 (vmbr0)
│   └── LAN: 10.0.20.1/24 (vmbr1)
├── CT 101: suricata-zeek [IN PROGRESS]
│   ├── Suricata IDS: eth1, ET Open rules [CONFIGURED]
│   └── Zeek NSM: eth1 [NOT YET INSTALLED]
├── Nginx Proxy Manager LXC [planned]
├── Tailscale LXC [planned]
├── Kali Linux VM [planned]
└── Windows 10 VM [planned, victim + honeypot]
```

---

## Network Map
| Network | Subnet | Purpose |
|---|---|---|
| Home LAN | 192.168.100.0/24 | Physical, router, management |
| Lab LAN | 10.0.20.0/24 | Internal VMs via pfSense |

---

## Build Phases

### Phase 1: Node 2 Foundation (current)
- [x] Proxmox installed and configured
- [x] pfSense VM running
- [x] Suricata LXC created and configured
- [ ] Verify Suricata service running
- [ ] Install and configure Zeek
- [ ] Install Filebeat, ship EVE JSON + Zeek logs to Elastic
- [ ] Nginx Proxy Manager LXC
- [ ] Tailscale LXC

### Phase 2: Node 1 SIEM
- [ ] Fix kibana_system password
- [ ] Elastic Agent + Fleet enrollment
- [ ] Sysmon + Suricata + Zeek logs into Elastic
- [ ] Prebuilt detection rules enabled
- [ ] First Kibana dashboard

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

---

## Key URLs
| Service | URL |
|---|---|
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |
| Router | http://192.168.100.1 |
| Proxmox | https://192.168.100.2:8006 |
| pfSense | http://192.168.100.144 |
| Suricata-Zeek LXC | ssh root@192.168.100.145 |

---

## Next Session Checklist
1. SSH into suricata-zeek: `ssh root@192.168.100.145`
2. Check Suricata: `systemctl status suricata`
3. Verify EVE JSON: `tail -f /var/log/suricata/eve.json`
4. Install Zeek
5. Configure Zeek on eth1
6. Install Filebeat
7. Ship logs to Elastic
