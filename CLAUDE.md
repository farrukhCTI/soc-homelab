# SOC Homelab - Project Memory

## Hardware
Windows Dell: i5-1035G1, 16GB RAM, Win11, Static IP 192.168.100.4
  Docker Desktop (WSL2 backend, 10GB memory limit)
  Drive: E:\soc-homelab

Dell E7250: i5-5300U, 8GB RAM, currently Ubuntu, will become Proxmox
  IP: 192.168.100.5 (planned)

## What Is Working
- Sysmon v15.15 installed with SwiftOnSecurity config (C:\Tools\Sysmon)
- Docker Desktop v29.2.1 running
- vm.max_map_count=262144 set for Elasticsearch
- WSL2 memory capped at 10GB via .wslconfig
- Elastic Stack 8.17.0 deploying (Elasticsearch + Kibana)

## Credentials
- Elasticsearch: elastic / SOCHomelab2026!
- Kibana: kibana_system password needs to be set after first boot

## Docker Compose Locations
- Elastic: E:\soc-homelab\docker\elastic\docker-compose.yml

## Network Plan
- Windows Dell: 192.168.100.4
- Proxmox E7250: 192.168.100.5
- pfSense LAN (blue team): 10.0.20.0/24
- pfSense DMZ (targets): 10.0.10.0/24
- pfSense attacker: 10.0.0.0/24

## Next Steps
- Set kibana_system password
- Install Elastic Agent on Windows
- Configure Sysmon log ingestion
- Enable detection rules
- Set static IP on Windows
