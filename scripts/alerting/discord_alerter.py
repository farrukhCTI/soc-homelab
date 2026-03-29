import requests
from datetime import datetime, timezone, timedelta
import time
import os

# CONFIG
ELASTICSEARCH_URL = "http://localhost:9200"
ELASTICSEARCH_USER = "elastic"
ELASTICSEARCH_PASS = "peu4Npiulfwtto77W7dDqA=="
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1485947997467578419/GD4mEc3KVv4VvC4e1jCvC3jFEP19vzjZGf5g8svBiNN-HJpECUeUZX2c91aZEEvk1qrw"
ALERTS_INDEX = ".alerts-security.alerts-default"
STATE_FILE = os.path.join(os.path.dirname(__file__), "last_run.txt")
POLL_INTERVAL_SECONDS = 300

def get_last_run():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return f.read().strip()
    dt = datetime.now(timezone.utc) - timedelta(minutes=10)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def save_last_run(timestamp):
    with open(STATE_FILE, "w") as f:
        f.write(timestamp)

def nested(d, path, default="N/A"):
    keys = path.split(".")
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d if d not in ({}, None, "") else default

def fetch_new_alerts(since):
    query = {
        "size": 20,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gt": since}}},
                    {"term": {"kibana.alert.status": "active"}}
                ]
            }
        },
        "_source": [
            "@timestamp",
            "kibana.alert.rule.name",
            "kibana.alert.severity",
            "kibana.alert.risk_score",
            "kibana.alert.uuid",
            "host",
            "user",
            "process"
        ]
    }
    try:
        response = requests.post(
            f"{ELASTICSEARCH_URL}/{ALERTS_INDEX}/_search",
            auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASS),
            headers={"Content-Type": "application/json"},
            json=query,
            timeout=10
        )
        response.raise_for_status()
        return response.json().get("hits", {}).get("hits", [])
    except Exception as e:
        print(f"[ERROR] Elasticsearch query failed: {e}")
        return []

def severity_emoji(severity):
    mapping = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🟢"
    }
    return mapping.get(str(severity).lower(), "⚪")

def build_discord_message(alert):
    src = alert.get("_source", {})

    rule_name  = nested(src, "kibana.alert.rule.name", "Unknown Rule")
    severity   = nested(src, "kibana.alert.severity", "unknown")
    risk_score = nested(src, "kibana.alert.risk_score", "N/A")
    timestamp  = src.get("@timestamp", "N/A")
    emoji      = severity_emoji(severity)

    host_obj    = src.get("host", {})
    user_obj    = src.get("user", {})
    process_obj = src.get("process", {})

    host    = host_obj.get("name", "N/A") if isinstance(host_obj, dict) else "N/A"
    user    = user_obj.get("name", "N/A") if isinstance(user_obj, dict) else "N/A"
    process = process_obj.get("name", "N/A") if isinstance(process_obj, dict) else "N/A"
    cmdline = process_obj.get("command_line", "") if isinstance(process_obj, dict) else ""

    if cmdline and len(cmdline) > 200:
        cmdline = cmdline[:200] + "..."

    lines = [
        f"{emoji} **KIBANA ALERT**",
        f"**Rule:** {rule_name}",
        f"**Severity:** {severity.upper()}  |  **Risk Score:** {risk_score}",
        f"**Host:** {host}  |  **User:** {user}",
        f"**Process:** {process}",
    ]
    if cmdline:
        lines.append(f"**CMD:** `{cmdline}`")
    lines.append(f"**Time:** {timestamp}")
    lines.append("─────────────────────────")

    return "\n".join(lines)

SENT_UUIDS = set()

def post_to_discord(message):
    payload = {"content": message}
    try:
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json=payload,
            timeout=10
        )
        if response.status_code == 204:
            print(f"[OK] Posted to Discord")
        else:
            print(f"[WARN] Discord returned {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[ERROR] Discord post failed: {e}")

def run():
    print(f"[*] Discord Alerter started. Polling every {POLL_INTERVAL_SECONDS}s")
    while True:
        since = get_last_run()
        print(f"[*] Checking for alerts since {since}")
        alerts = fetch_new_alerts(since)

        if alerts:
            new_count = 0
            latest_timestamp = since
            for alert in alerts:
                src = alert.get("_source", {})
                uuid = nested(src, "kibana.alert.uuid", alert.get("_id", ""))
                if uuid in SENT_UUIDS:
                    continue
                SENT_UUIDS.add(uuid)
                msg = build_discord_message(alert)
                post_to_discord(msg)
                new_count += 1
                ts = src.get("@timestamp", "")
                if ts > latest_timestamp:
                    latest_timestamp = ts
                time.sleep(1)
            if new_count:
                print(f"[*] Sent {new_count} new alert(s)")
                save_last_run(latest_timestamp)
            else:
                print("[*] All alerts already sent")
        else:
            print("[*] No new alerts")

        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    run()