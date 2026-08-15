# Historical Lab: Original Proxmox Range

This document describes the original two node lab as it was built and operated. This environment is decommissioned. It is not shipped in this repository and cannot be deployed from what is here today. It is retained as documentation of work that was done, evidence for the investigation reports, and context for the architecture decisions that shaped Argus.

If you are looking for what actually runs today from this repository, see [CURRENT-DEMO.md](CURRENT-DEMO.md).

---

## What Was Built

A two node segmented lab designed so that all attacker to victim traffic was forced through a monitored pfSense interface, guaranteeing Suricata visibility regardless of attacker behavior.

- **Node 1:** Dell Inspiron 3593, i5-1035G1, 16GB RAM. Ran Elasticsearch, Kibana, Fleet Server, and Elastic Agent. This node still exists and is now the base for the portable demo.
- **Node 2:** Dell E7250, i5-5300U, 8GB RAM. Ran Proxmox VE, hosting three VMs: pfSense (router, IDS, NDR sensor), a Kali Linux attacker, and a Windows 10 victim (DESKTOP-MM1REM9). This node was wiped and its Proxmox installation is gone.

## Network Topology

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
    |   +-- LAN  -> 10.0.20.1/24   (vmbr1, Victim Network)
    |   +-- OPT1 -> 10.0.30.1/24   (vmbr2, Attack Network)
    |        +-- Suricata (monitoring OPT1 / vtnet2)
    |        +-- Filebeat 7.14.0 (EVE JSON -> ES :9200)
    |
    +-- VM 101: Kali Linux
    |   +-- 10.0.30.10 (Attack Network, vmbr2)
    |
    +-- VM 102: Windows 10 Victim (DESKTOP-MM1REM9)
        +-- 10.0.20.10 (Victim Network, vmbr1)
            +-- Sysmon v15.20 + Elastic Agent 8.17.0
```

Monitored traffic path (Suricata visible):

```
Kali (10.0.30.10) -> pfSense OPT1 (Suricata) -> pfSense LAN -> Victim (10.0.20.10)
```

Unmonitored path (Suricata blind spot):

```
Kali -> Node 1 (192.168.100.143)
```

## What This Environment Produced

- IR-001 through IR-005: a connected kill chain investigation, Defender on throughout, all LOLBin based techniques, no malware required
- The cross-layer correlation finding in IR-005: 23 Sysmon EID 3 events and 23 Suricata HTTP flow records independently confirming the same C2 channel, collected by two sensors with no shared data path
- Background automation via Atomic Red Team techniques run probabilistically every 30 minutes through Windows Task Scheduler on the victim VM, used to keep the lab producing telemetry autonomously during the build and validation phase
- The original Hermes agent, a Discord connected assistant that queried Elasticsearch and Argus on request, ran attack simulations, and generated case reports. Hermes ran on Node 2 and was never committed to this repository. Its source code did not survive the wipe. Sample output from Hermes runs, including CASE-020, is preserved as reference material, see `hermes/legacy-output-examples/` in this repository.

## Current Status

Node 2 was wiped and Windows 10 was reinstalled without Proxmox. This lab cannot currently be reproduced from this repository and is not part of the portable demo. Anything from this environment described elsewhere in this repository should be understood as historical unless explicitly marked otherwise.

The screenshots, diagrams, and raw event data collected during this build remain in the repository and are used as evidence in the investigation reports. That evidence is real and was collected from live telemetry at the time. It is not something a person cloning this repository today can reproduce by running anything here, and no part of this repository claims otherwise.
