# SOC + CTI Homelab

Integrated Security Operations Center and Cyber Threat Intelligence homelab built on constrained hardware, targeting Pakistan SOC market roles (IT Butler, enterprise SOC teams).

## Hardware
- **SOC Core**: Dell i5-1035G1, 16GB RAM, Windows 11, Docker Desktop
- **Attack Lab**: Dell E7250 i5-5300U, 8GB RAM, Proxmox VE (planned)

## Stack
- Elastic SIEM (Elasticsearch + Kibana + Fleet)
- MISP (threat intelligence platform)
- TheHive + Cortex (case management + enrichment)
- Shuffle SOAR (orchestration + automation)
- Suricata IDS (network monitoring)
- pfSense (firewall + network segmentation)
- Claude API (AI-assisted alert triage)
- Sysmon (endpoint telemetry)

## Build Status
- [x] Sysmon installed with SwiftOnSecurity config
- [x] Docker Desktop running (WSL2 backend)
- [ ] Elastic SIEM deployed
- [ ] Elastic Agent enrolled
- [ ] Detection rules configured
- [ ] Proxmox installed on E7250
- [ ] pfSense network segmentation
- [ ] Suricata IDS
- [ ] TheHive + Cortex
- [ ] Shuffle SOAR
- [ ] MISP threat intel
- [ ] Claude API triage tooling

## Author
Farrukh - CTI analyst transitioning into SOC operations
