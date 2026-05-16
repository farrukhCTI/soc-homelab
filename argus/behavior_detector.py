from elasticsearch import Elasticsearch
import os
import time
from datetime import datetime, timezone

ES_URL  = os.environ.get("ES_URL", "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS))

# ---------------------------------------------------------------------------
# BEHAVIORAL SIGNAL PROFILES
#
# Argus is a behavior enrichment and case correlation layer, NOT a detection
# engine. Elastic/Sysmon rules handle detection. These profiles define
# suspicious activity signals that Argus normalizes into investigation-ready
# behaviors for analyst review.
#
# Important: these are behavioral signals, not precise detections. They use
# substring matching and will produce false positives on benign admin activity.
# Confidence and behavior_class fields reflect signal quality per profile.
# Analysts should treat LOW confidence signals as context, not findings.
#
# Suppression: MAX_BEHAVIORS_PER_EVENT caps how many profiles fire per raw
# event. Highest priority_score profiles win. This prevents one Atomic test
# from flooding the behavior index with near-duplicate entries.
#
# Profile fields:
#   event_codes    : Sysmon EIDs to query (1=process, 10=proc access, 11=file, 13=registry)
#   process        : process image substrings (EID 1 only)
#   cmd_contains   : ALL of these must appear in CommandLine (case-insensitive)
#   cmd_any        : ANY of these must appear in CommandLine (case-insensitive)
#   target_proc    : TargetImage substring for EID 10 (process access)
#   reg_path       : TargetObject substring for EID 13 (registry write)
#   file_ext       : TargetFilename extension for EID 11 (file creation)
#   file_path      : TargetFilename substring for EID 11
#   confidence     : low | medium | high — signal reliability
#   behavior_class : recon | execution | persistence | evasion |
#                    credential_access | lateral_movement | collection |
#                    exfiltration | impact
# ---------------------------------------------------------------------------

MAX_BEHAVIORS_PER_EVENT = 3  # cap per raw source event, highest priority wins

DETECTION_PROFILES = {

    # --- EXECUTION -----------------------------------------------------------

    "powershell_encoded_exec": {
        "event_codes": [1],
        "process": ["powershell.exe"],
        "cmd_any": ["-enc", "-encodedcommand"],
        "technique": "T1059.001",
        "tactic": "EXECUTION",
        "description": "PowerShell Encoded Command Execution",
        "severity": "HIGH",
        "priority_score": 75,
        "confidence": "high",
        "behavior_class": "execution",
    },
    "powershell_download_cradle": {
        "event_codes": [1],
        "process": ["powershell.exe"],
        "cmd_any": ["downloadstring", "downloadfile", "invoke-webrequest"],
        "technique": "T1059.001",
        "tactic": "EXECUTION",
        "description": "PowerShell Download Cradle",
        "severity": "HIGH",
        "priority_score": 80,
        "confidence": "high",
        "behavior_class": "execution",
    },
    "powershell_bypass_policy": {
        "event_codes": [1],
        "process": ["powershell.exe"],
        "cmd_any": ["-executionpolicy bypass", "-ep bypass"],
        "technique": "T1059.001",
        "tactic": "EXECUTION",
        "description": "PowerShell Execution Policy Bypass",
        "severity": "MEDIUM",
        "priority_score": 65,
        "confidence": "medium",
        "behavior_class": "evasion",
    },
    "cmd_shell_execution": {
        "event_codes": [1],
        "process": ["cmd.exe"],
        "cmd_any": ["/c", "/k"],
        "technique": "T1059.003",
        "tactic": "EXECUTION",
        "description": "Windows Command Shell Execution",
        "severity": "LOW",
        "priority_score": 30,
        "confidence": "low",
        "behavior_class": "execution",
    },
    "wscript_execution": {
        "event_codes": [1],
        "process": ["wscript.exe", "cscript.exe"],
        "technique": "T1059.005",
        "tactic": "EXECUTION",
        "description": "Windows Script Host Execution",
        "severity": "MEDIUM",
        "priority_score": 65,
        "confidence": "medium",
        "behavior_class": "execution",
    },
    "mshta_remote_script": {
        "event_codes": [1],
        "process": ["mshta.exe"],
        "cmd_any": ["http://", "https://", "vbscript:", "javascript:"],
        "technique": "T1218.005",
        "tactic": "DEFENSE_EVASION",
        "description": "MSHTA Executing Remote Script",
        "severity": "HIGH",
        "priority_score": 80,
        "confidence": "high",
        "behavior_class": "execution",
    },
    "wmic_process_create": {
        "event_codes": [1],
        "process": ["wmic.exe"],
        "cmd_any": ["process call create"],
        "technique": "T1047",
        "tactic": "EXECUTION",
        "description": "WMIC Remote Process Creation",
        "severity": "HIGH",
        "priority_score": 80,
        "confidence": "high",
        "behavior_class": "execution",
    },
    "certutil_download": {
        "event_codes": [1],
        "process": ["certutil.exe"],
        "cmd_any": ["-urlcache", "-decode"],
        "technique": "T1105",
        "tactic": "EXECUTION",
        "description": "Certutil Used for Download or Decode",
        "severity": "HIGH",
        "priority_score": 82,
        "confidence": "high",
        "behavior_class": "execution",
    },

    # --- PERSISTENCE ---------------------------------------------------------

    "schtasks_creation": {
        "event_codes": [1],
        "process": ["schtasks.exe"],
        "cmd_any": ["/create", "-create"],
        "technique": "T1053.005",
        "tactic": "PERSISTENCE",
        "description": "Scheduled Task Created via Schtasks",
        "severity": "HIGH",
        "priority_score": 80,
        "confidence": "high",
        "behavior_class": "persistence",
    },
    "at_job_creation": {
        "event_codes": [1],
        "process": ["at.exe"],
        "technique": "T1053.002",
        "tactic": "PERSISTENCE",
        "description": "Legacy AT Scheduled Job Creation",
        "severity": "HIGH",
        "priority_score": 78,
        "confidence": "high",
        "behavior_class": "persistence",
    },
    "sc_service_creation": {
        "event_codes": [1],
        "process": ["sc.exe"],
        "cmd_any": ["create"],
        "technique": "T1543.003",
        "tactic": "PERSISTENCE",
        "description": "New Windows Service Created via SC",
        "severity": "HIGH",
        "priority_score": 82,
        "confidence": "high",
        "behavior_class": "persistence",
    },
    "net_user_created": {
        "event_codes": [1],
        "process": ["net.exe", "net1.exe"],
        "cmd_any": ["user /add"],
        "technique": "T1136.001",
        "tactic": "PERSISTENCE",
        "description": "Local User Account Created",
        "severity": "HIGH",
        "priority_score": 85,
        "confidence": "high",
        "behavior_class": "persistence",
    },
    "registry_run_key_write": {
        "event_codes": [13],
        "reg_path": ["\\CurrentVersion\\Run\\", "\\CurrentVersion\\RunOnce\\"],
        "technique": "T1547.001",
        "tactic": "PERSISTENCE",
        "description": "Registry Run Key Modification",
        "severity": "HIGH",
        "priority_score": 85,
        "confidence": "high",
        "behavior_class": "persistence",
    },
    "startup_folder_drop": {
        "event_codes": [11],
        "file_path": ["\\Start Menu\\Programs\\Startup\\", "\\Startup\\"],
        "file_ext": [".exe", ".bat", ".ps1", ".vbs", ".lnk"],
        "technique": "T1547.001",
        "tactic": "PERSISTENCE",
        "description": "File Dropped in Startup Folder",
        "severity": "HIGH",
        "priority_score": 85,
        "confidence": "high",
        "behavior_class": "persistence",
    },

    # --- DEFENSE EVASION -----------------------------------------------------

    "regsvr32_lolbin": {
        "event_codes": [1],
        "process": ["regsvr32.exe"],
        "cmd_any": ["scrobj", "http://", "https://"],
        "technique": "T1218.010",
        "tactic": "DEFENSE_EVASION",
        "description": "Regsvr32 LOLBin Execution",
        "severity": "HIGH",
        "priority_score": 78,
        "confidence": "high",
        "behavior_class": "evasion",
    },
    "rundll32_suspicious": {
        "event_codes": [1],
        "process": ["rundll32.exe"],
        "cmd_any": ["javascript:", "vbscript:", "http://"],
        "technique": "T1218.011",
        "tactic": "DEFENSE_EVASION",
        "description": "Rundll32 Suspicious Execution",
        "severity": "HIGH",
        "priority_score": 78,
        "confidence": "high",
        "behavior_class": "evasion",
    },
    "base64_in_cmdline": {
        "event_codes": [1],
        "process": ["powershell.exe"],
        "cmd_any": ["frombase64string"],
        "technique": "T1027",
        "tactic": "DEFENSE_EVASION",
        "description": "Base64 Encoded Payload in Command Line",
        "severity": "HIGH",
        "priority_score": 78,
        "confidence": "medium",
        "behavior_class": "evasion",
    },
    "iex_obfuscation": {
        "event_codes": [1],
        "process": ["powershell.exe"],
        "cmd_any": ["invoke-expression"],
        "technique": "T1027",
        "tactic": "DEFENSE_EVASION",
        "description": "IEX Obfuscation Detected",
        "severity": "HIGH",
        "priority_score": 80,
        "confidence": "medium",
        "behavior_class": "evasion",
    },
    "defender_disabled_ps": {
        "event_codes": [1],
        "process": ["powershell.exe"],
        "cmd_any": ["set-mppreference", "disablerealtimemonitoring", "disableioavprotection"],
        "technique": "T1562.001",
        "tactic": "DEFENSE_EVASION",
        "description": "Windows Defender Disabled via PowerShell",
        "severity": "CRITICAL",
        "priority_score": 92,
        "confidence": "high",
        "behavior_class": "evasion",
    },
    "attrib_hidden": {
        "event_codes": [1],
        "process": ["attrib.exe"],
        "cmd_any": ["+h", "+s"],
        "technique": "T1564.001",
        "tactic": "DEFENSE_EVASION",
        "description": "File or Directory Hidden via Attrib",
        "severity": "MEDIUM",
        "priority_score": 55,
        "confidence": "medium",
        "behavior_class": "evasion",
    },
    "msbuild_exec": {
        "event_codes": [1],
        "process": ["msbuild.exe"],
        "technique": "T1127.001",
        "tactic": "DEFENSE_EVASION",
        "description": "MSBuild Used for Code Execution",
        "severity": "HIGH",
        "priority_score": 80,
        "confidence": "high",
        "behavior_class": "evasion",
    },
    "installutil_exec": {
        "event_codes": [1],
        "process": ["installutil.exe"],
        "technique": "T1218.004",
        "tactic": "DEFENSE_EVASION",
        "description": "InstallUtil Used for Code Execution",
        "severity": "HIGH",
        "priority_score": 80,
        "confidence": "high",
        "behavior_class": "evasion",
    },

    # --- DISCOVERY -----------------------------------------------------------

    "whoami_execution": {
        "event_codes": [1],
        "process": ["whoami.exe"],
        "technique": "T1033",
        "tactic": "DISCOVERY",
        "description": "System Owner/User Discovery",
        "severity": "LOW",
        "priority_score": 20,
        "confidence": "low",
        "behavior_class": "recon",
    },
    "systeminfo_execution": {
        "event_codes": [1],
        "process": ["systeminfo.exe"],
        "technique": "T1082",
        "tactic": "DISCOVERY",
        "description": "System Information Discovery",
        "severity": "LOW",
        "priority_score": 20,
        "confidence": "low",
        "behavior_class": "recon",
    },
    "netstat_discovery": {
        "event_codes": [1],
        "process": ["netstat.exe"],
        "technique": "T1049",
        "tactic": "DISCOVERY",
        "description": "Network Connections Discovery",
        "severity": "LOW",
        "priority_score": 20,
        "confidence": "low",
        "behavior_class": "recon",
    },
    "ipconfig_discovery": {
        "event_codes": [1],
        "process": ["ipconfig.exe"],
        "technique": "T1016",
        "tactic": "DISCOVERY",
        "description": "Network Configuration Discovery",
        "severity": "LOW",
        "priority_score": 20,
        "confidence": "low",
        "behavior_class": "recon",
    },
    "net_account_enum": {
        "event_codes": [1],
        "process": ["net.exe", "net1.exe"],
        "cmd_any": ["localgroup", "group administrators"],
        "technique": "T1087.001",
        "tactic": "DISCOVERY",
        "description": "Local Account Enumeration",
        "severity": "LOW",
        "priority_score": 25,
        "confidence": "low",
        "behavior_class": "recon",
    },
    "reg_query": {
        "event_codes": [1],
        "process": ["reg.exe"],
        "cmd_any": ["query", "export"],
        "technique": "T1012",
        "tactic": "DISCOVERY",
        "description": "Registry Query or Export",
        "severity": "LOW",
        "priority_score": 25,
        "confidence": "low",
        "behavior_class": "recon",
    },
    "tasklist_discovery": {
        "event_codes": [1],
        "process": ["tasklist.exe"],
        "technique": "T1057",
        "tactic": "DISCOVERY",
        "description": "Process Discovery via Tasklist",
        "severity": "LOW",
        "priority_score": 20,
        "confidence": "low",
        "behavior_class": "recon",
    },
    "ping_sweep": {
        "event_codes": [1],
        "process": ["ping.exe"],
        "cmd_any": ["-n ", "/n "],
        "technique": "T1018",
        "tactic": "DISCOVERY",
        "description": "Remote System Discovery via Ping",
        "severity": "LOW",
        "priority_score": 25,
        "confidence": "low",
        "behavior_class": "recon",
    },
    "nltest_domain_trust": {
        "event_codes": [1],
        "process": ["nltest.exe"],
        "cmd_any": ["/domain_trusts", "/trusted_domains", "/dclist"],
        "technique": "T1482",
        "tactic": "DISCOVERY",
        "description": "Domain Trust Discovery via NLTest",
        "severity": "MEDIUM",
        "priority_score": 55,
        "confidence": "high",
        "behavior_class": "recon",
    },
    "wmic_software_discovery": {
        "event_codes": [1],
        "process": ["wmic.exe"],
        "cmd_any": ["product get", "qfe"],
        "technique": "T1518",
        "tactic": "DISCOVERY",
        "description": "Installed Software Discovery via WMIC",
        "severity": "LOW",
        "priority_score": 20,
        "confidence": "low",
        "behavior_class": "recon",
    },

    # --- CREDENTIAL ACCESS ---------------------------------------------------

    "lsass_process_access": {
        "event_codes": [10],
        "target_proc": ["lsass.exe"],
        "technique": "T1003.001",
        "tactic": "CREDENTIAL_ACCESS",
        "description": "LSASS Memory Access (Credential Dumping)",
        "severity": "CRITICAL",
        "priority_score": 95,
        "confidence": "high",
        "behavior_class": "credential_access",
    },
    "mimikatz_cmdline": {
        "event_codes": [1],
        "process": ["powershell.exe", "cmd.exe", "mimikatz.exe"],
        "cmd_any": ["sekurlsa", "lsadump", "privilege::debug", "invoke-mimikatz"],
        "technique": "T1003.001",
        "tactic": "CREDENTIAL_ACCESS",
        "description": "Mimikatz Indicators in Command Line",
        "severity": "CRITICAL",
        "priority_score": 95,
        "confidence": "high",
        "behavior_class": "credential_access",
    },
    "sam_hive_access": {
        "event_codes": [1],
        "process": ["reg.exe"],
        "cmd_any": ["save hklm\\sam", "save hklm\\system", "save hklm\\security"],
        "technique": "T1003.002",
        "tactic": "CREDENTIAL_ACCESS",
        "description": "SAM Registry Hive Access",
        "severity": "CRITICAL",
        "priority_score": 95,
        "confidence": "high",
        "behavior_class": "credential_access",
    },

    # --- LATERAL MOVEMENT ----------------------------------------------------

    "psexec_lateral": {
        "event_codes": [1],
        "process": ["psexec.exe", "psexec64.exe"],
        "technique": "T1021.002",
        "tactic": "LATERAL_MOVEMENT",
        "description": "PsExec Lateral Movement",
        "severity": "HIGH",
        "priority_score": 88,
        "confidence": "high",
        "behavior_class": "lateral_movement",
    },
    "rdp_initiated": {
        "event_codes": [1],
        "process": ["mstsc.exe"],
        "technique": "T1021.001",
        "tactic": "LATERAL_MOVEMENT",
        "description": "RDP Session Initiated",
        "severity": "LOW",
        "priority_score": 25,
        "confidence": "low",
        "behavior_class": "lateral_movement",
    },

    # --- COLLECTION ----------------------------------------------------------

    "archive_sensitive_files": {
        "event_codes": [1],
        "process": ["7z.exe", "7za.exe", "winrar.exe", "rar.exe"],
        "technique": "T1560.001",
        "tactic": "COLLECTION",
        "description": "Archiving via 7zip or WinRAR",
        "severity": "MEDIUM",
        "priority_score": 55,
        "confidence": "low",
        "behavior_class": "collection",
    },
    "clipboard_access": {
        "event_codes": [1],
        "process": ["powershell.exe"],
        "cmd_any": ["get-clipboard", "windows.forms.clipboard", "getdataobject"],
        "technique": "T1115",
        "tactic": "COLLECTION",
        "description": "PowerShell Accessing Clipboard",
        "severity": "MEDIUM",
        "priority_score": 55,
        "confidence": "medium",
        "behavior_class": "collection",
    },

    # --- EXFILTRATION --------------------------------------------------------

    "curl_wget_transfer": {
        "event_codes": [1],
        "process": ["curl.exe", "wget.exe"],
        "cmd_any": ["-T ", "--upload-file"],
        "technique": "T1048",
        "tactic": "EXFILTRATION",
        "description": "Curl or Wget Outbound Data Transfer",
        "severity": "HIGH",
        "priority_score": 80,
        "confidence": "medium",
        "behavior_class": "exfiltration",
    },

    # --- IMPACT --------------------------------------------------------------

    "vss_deletion": {
        "event_codes": [1],
        "process": ["vssadmin.exe", "wmic.exe"],
        "cmd_any": ["delete shadows", "shadowcopy delete"],
        "technique": "T1490",
        "tactic": "IMPACT",
        "description": "Volume Shadow Copy Deletion",
        "severity": "CRITICAL",
        "priority_score": 95,
        "confidence": "high",
        "behavior_class": "impact",
    },
    "bcdedit_recovery": {
        "event_codes": [1],
        "process": ["bcdedit.exe"],
        "cmd_any": ["recoveryenabled no", "bootstatuspolicy ignoreallfailures"],
        "technique": "T1490",
        "tactic": "IMPACT",
        "description": "BCDEdit Disabling System Recovery",
        "severity": "CRITICAL",
        "priority_score": 95,
        "confidence": "high",
        "behavior_class": "impact",
    },
    "event_log_cleared": {
        "event_codes": [1],
        "process": ["wevtutil.exe"],
        "cmd_any": ["cl ", "clear-log"],
        "technique": "T1070.001",
        "tactic": "IMPACT",
        "description": "Event Log Cleared via Wevtutil",
        "severity": "HIGH",
        "priority_score": 88,
        "confidence": "high",
        "behavior_class": "impact",
    },

    # --- EXECUTABLE DROPPED --------------------------------------------------

    "exe_dropped_temp": {
        "event_codes": [11],
        "file_path": ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\"],
        "file_ext": [".exe", ".dll", ".bat", ".ps1"],
        "technique": "T1105",
        "tactic": "EXECUTION",
        "description": "Executable Dropped in Temp Directory",
        "severity": "HIGH",
        "priority_score": 80,
        "confidence": "medium",
        "behavior_class": "execution",
    },
}

# ---------------------------------------------------------------------------
# TACTIC WEIGHTS — used when profile does not set severity/priority_score
# ---------------------------------------------------------------------------
TACTIC_WEIGHTS = {
    "DISCOVERY":          {"severity": "LOW",      "priority_score": 20},
    "EXECUTION":          {"severity": "MEDIUM",   "priority_score": 60},
    "PERSISTENCE":        {"severity": "HIGH",     "priority_score": 80},
    "DEFENSE_EVASION":    {"severity": "MEDIUM",   "priority_score": 70},
    "C2":                 {"severity": "HIGH",     "priority_score": 90},
    "CREDENTIAL_ACCESS":  {"severity": "CRITICAL", "priority_score": 95},
    "LATERAL_MOVEMENT":   {"severity": "HIGH",     "priority_score": 85},
    "COLLECTION":         {"severity": "MEDIUM",   "priority_score": 55},
    "EXFILTRATION":       {"severity": "HIGH",     "priority_score": 82},
    "IMPACT":             {"severity": "CRITICAL", "priority_score": 95},
    "PRIVILEGE_ESCALATION": {"severity": "HIGH",   "priority_score": 85},
    "INITIAL_ACCESS":     {"severity": "HIGH",     "priority_score": 80},
}

last_seen = {1: None, 10: None, 11: None, 13: None}


def match_profile(profile, src, eid):
    """Return (matched, fire_reasons) for a given profile and event source."""

    ed = src.get("winlog", {}).get("event_data", {})
    image = ed.get("Image", "").lower()
    cmd   = ed.get("CommandLine", "").lower()

    reasons = []

    # EID 1: process creation
    if eid == 1:
        procs = profile.get("process", [])
        if procs:
            if not any(p.lower() in image for p in procs):
                return False, []
            reasons.append(f"Process matched: {image.split(chr(92))[-1]}")

        cmd_any = profile.get("cmd_any", [])
        if cmd_any:
            hit = next((p for p in cmd_any if p.lower() in cmd), None)
            if not hit:
                return False, []
            reasons.append(f"CommandLine contains: {hit}")

        cmd_all = profile.get("cmd_contains", [])
        if cmd_all:
            missing = [p for p in cmd_all if p.lower() not in cmd]
            if missing:
                return False, []
            reasons.append(f"CommandLine pattern matched: {', '.join(cmd_all)}")

    # EID 10: process access
    elif eid == 10:
        target = ed.get("TargetImage", "").lower()
        targets = profile.get("target_proc", [])
        if targets:
            if not any(t.lower() in target for t in targets):
                return False, []
            reasons.append(f"Process access to: {target.split(chr(92))[-1]}")

    # EID 11: file creation
    elif eid == 11:
        file_target = ed.get("TargetFilename", "").lower()
        file_paths = profile.get("file_path", [])
        file_exts  = profile.get("file_ext", [])

        if file_paths:
            if not any(p.lower() in file_target for p in file_paths):
                return False, []
            reasons.append(f"File in suspicious path: {file_target}")

        if file_exts:
            if not any(file_target.endswith(e.lower()) for e in file_exts):
                return False, []
            reasons.append(f"Suspicious file extension: {file_target.split('.')[-1]}")

    # EID 13: registry value set
    elif eid == 13:
        reg_target = ed.get("TargetObject", "").lower()
        reg_paths  = profile.get("reg_path", [])
        if reg_paths:
            if not any(p.lower() in reg_target for p in reg_paths):
                return False, []
            reasons.append(f"Registry key written: {reg_target}")

    return True, reasons


def run_detection_for_eid(eid):
    global last_seen

    gte = last_seen[eid] if last_seen[eid] else "now-1h"

    resp = es.search(
        index="logs-winlog.winlog-default",
        size=200,
        sort=[{"@timestamp": {"order": "asc"}}],
        query={
            "bool": {
                "must": {"match": {"event.code": str(eid)}},
                "filter": {"range": {"@timestamp": {"gt": gte}}}
            }
        }
    )

    hits = resp["hits"]["hits"]
    written = 0

    # Profiles relevant to this EID
    relevant = {
        name: p for name, p in DETECTION_PROFILES.items()
        if eid in p.get("event_codes", [])
    }

    for hit in hits:
        doc_id = hit["_id"]
        src    = hit["_source"]
        host   = src.get("host", {}).get("name", "unknown")
        ts     = src.get("@timestamp", "")
        ed     = src.get("winlog", {}).get("event_data", {})
        image  = ed.get("Image", "")
        cmd    = ed.get("CommandLine", "")

        # Collect all matching profiles for this event, then apply suppression cap.
        # Highest priority_score profiles win. This prevents one Atomic test from
        # flooding the behavior index with near-duplicate behaviors.
        matches = []
        for profile_name, profile in relevant.items():
            matched, reasons = match_profile(profile, src, eid)
            if matched:
                matches.append((profile_name, profile, reasons))

        # Sort by priority descending, keep top MAX_BEHAVIORS_PER_EVENT
        matches.sort(key=lambda x: x[1].get("priority_score", 0), reverse=True)
        matches = matches[:MAX_BEHAVIORS_PER_EVENT]

        for profile_name, profile, reasons in matches:
            technique    = profile["technique"]
            tactic       = profile["tactic"]
            description  = profile["description"]
            severity     = profile.get("severity") or TACTIC_WEIGHTS.get(tactic, {}).get("severity", "LOW")
            priority     = profile.get("priority_score") or TACTIC_WEIGHTS.get(tactic, {}).get("priority_score", 50)
            confidence   = profile.get("confidence", "low")
            beh_class    = profile.get("behavior_class", "unknown")

            # Stable index ID: source event + profile name prevents duplicates on reindex
            behavior_id  = f"BEH-{doc_id[:8].upper()}-{profile_name[:8].upper()}"
            index_id     = f"{doc_id}-{profile_name}"

            behavior_doc = {
                "behavior_id":      behavior_id,
                "profile":          profile_name,
                "host":             host,
                "timestamp":        ts,
                "detected_at":      datetime.now(timezone.utc).isoformat(),
                "event_code":       eid,
                "image":            image,
                "command_line":     cmd,
                "tactic":           tactic,
                "mitre_technique":  technique,
                "description":      description,
                "severity":         severity,
                "priority_score":   priority,
                "confidence":       confidence,
                "behavior_class":   beh_class,
                "status":           "NEW",
                "fire_reasons":     reasons + [f"MITRE {technique} pattern matched"],
                "source_event_id":  doc_id,
            }

            es.index(index="argus-behaviors", id=index_id, document=behavior_doc)
            written += 1

    if hits:
        last_seen[eid] = hits[-1]["_source"]["@timestamp"]

    return len(hits), written


def run_detection():
    total_scanned = 0
    total_written = 0
    for eid in [1, 10, 11, 13]:
        scanned, written = run_detection_for_eid(eid)
        total_scanned += scanned
        total_written += written

    print(
        f"[{datetime.now(timezone.utc).isoformat()}] "
        f"Cycle done. Scanned: {total_scanned} | Behaviors written: {total_written}"
    )


print("Argus behavior detector starting. Poll interval: 60s. Ctrl+C to stop.")
print(f"Loaded {len(DETECTION_PROFILES)} detection profiles across EIDs 1, 10, 11, 13.")
while True:
    run_detection()
    time.sleep(60)
