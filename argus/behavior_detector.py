from elasticsearch import Elasticsearch
import os
import time
from datetime import datetime, timezone

ES_URL  = os.environ.get("ES_URL", "http://192.168.100.143:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS))

MITRE_MAP = {
    "whoami.exe":     ("T1033",     "DISCOVERY",       "System Owner/User Discovery"),
    "systeminfo.exe": ("T1082",     "DISCOVERY",       "System Information Discovery"),
    "hostname.exe":   ("T1082",     "DISCOVERY",       "System Information Discovery"),
    "netstat.exe":    ("T1049",     "DISCOVERY",       "Network Connections Discovery"),
    "ipconfig.exe":   ("T1016",     "DISCOVERY",       "Network Config Discovery"),
    "net.exe":        ("T1087.001", "DISCOVERY",       "Account Discovery Local"),
    "net1.exe":       ("T1087.001", "DISCOVERY",       "Account Discovery Local"),
    "schtasks.exe":   ("T1053.005", "PERSISTENCE",     "Scheduled Task Creation"),
    "mshta.exe":      ("T1218.005", "DEFENSE_EVASION", "Mshta LOLBin Execution"),
    "certutil.exe":   ("T1105",     "C2",              "Certutil File Transfer"),
    "regsvr32.exe":   ("T1218.010", "DEFENSE_EVASION", "Regsvr32 LOLBin Execution"),
    "wscript.exe":    ("T1218.005", "DEFENSE_EVASION", "WScript LOLBin Execution"),
    "reg.exe":        ("T1012",     "DISCOVERY",       "Query Registry"),
    "cmd.exe":        ("T1059.003", "EXECUTION",       "Windows Command Shell"),
}

# Tactic-based severity and priority scoring
TACTIC_WEIGHTS = {
    "DISCOVERY":       {"severity": "LOW",      "priority_score": 20},
    "EXECUTION":       {"severity": "MEDIUM",   "priority_score": 60},
    "PERSISTENCE":     {"severity": "HIGH",     "priority_score": 80},
    "DEFENSE_EVASION": {"severity": "MEDIUM",   "priority_score": 70},
    "C2":              {"severity": "HIGH",     "priority_score": 90},
    "CREDENTIAL":      {"severity": "HIGH",     "priority_score": 85},
}

# Start from 1 hour ago on first run
last_seen = None

def run_detection():
    global last_seen

    if last_seen is None:
        gte = "now-1h"
    else:
        gte = last_seen

    resp = es.search(
        index="logs-winlog.winlog-default",
        size=100,
        sort=[{"@timestamp": {"order": "asc"}}],
        query={
            "bool": {
                "must": {"match": {"event.code": "1"}},
                "filter": {
                    "range": {
                        "@timestamp": {"gt": gte}
                    }
                }
            }
        }
    )

    hits = resp["hits"]["hits"]
    written = 0

    for hit in hits:
        doc_id = hit["_id"]
        src = hit["_source"]
        image = src.get("winlog", {}).get("event_data", {}).get("Image", "")
        cmd   = src.get("winlog", {}).get("event_data", {}).get("CommandLine", "")
        host  = src.get("host", {}).get("name", "unknown")
        ts    = src.get("@timestamp", "")

        image_lower = image.lower()
        matched_proc = None
        for proc in MITRE_MAP:
            if proc in image_lower:
                matched_proc = proc
                break

        if matched_proc:
            technique, tactic, description = MITRE_MAP[matched_proc]
            
            # Get tactic-based severity and priority_score
            weights = TACTIC_WEIGHTS.get(tactic, {"severity": "LOW", "priority_score": 50})
            severity = weights["severity"]
            priority_score = weights["priority_score"]
            
            behavior_doc = {
                "behavior_id":     "BEH-" + doc_id[:8].upper(),
                "host":            host,
                "timestamp":       ts,
                "detected_at":     datetime.now(timezone.utc).isoformat(),
                "image":           image,
                "command_line":    cmd,
                "tactic":          tactic,
                "mitre_technique": technique,
                "description":     description,
                "severity":        severity,
                "priority_score":  priority_score,
                "status":          "NEW",
                "fire_reasons":    [
                    f"{matched_proc} execution detected",
                    f"MITRE {technique} pattern matched"
                ],
                "source_event_id": doc_id
            }
            es.index(index="argus-behaviors", id=doc_id, document=behavior_doc)
            written += 1

    # Update cursor to the timestamp of the last event seen
    if hits:
        last_seen = hits[-1]["_source"]["@timestamp"]

    print(f"[{datetime.now(timezone.utc).isoformat()}] Cycle done. Events scanned: {len(hits)} | Behaviors written: {written} | Cursor: {last_seen}")

print("Argus behavior detector starting. Poll interval: 60s. Ctrl+C to stop.")
while True:
    run_detection()
    time.sleep(60)
