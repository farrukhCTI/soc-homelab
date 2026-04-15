"""
case_builder.py

Reads argus-behaviors-*, groups behaviors into cases.
Grouping rule: behaviors sharing host + 30min window = one case.

Run once, processes all behaviors without case_id assigned.
Writes to argus-cases-* index.

USAGE:
    python case_builder.py
"""

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, UTC
import sys
import os
import time

# ES connection - matches behavior_detector.py pattern
ES_URL  = os.environ.get("ES_URL", "http://192.168.100.143:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

es = Elasticsearch(
    ES_URL,
    basic_auth=(ES_USER, ES_PASS),
    request_timeout=30
)

def get_last_case_number():
    """Query argus-cases for highest case number, return as int."""
    try:
        resp = es.search(
            index="argus-cases",
            body={
                "size": 1,
                "sort": [{"created_at": {"order": "desc"}}],
                "_source": ["case_id"]
            }
        )
        if resp['hits']['total']['value'] > 0:
            last_id = resp['hits']['hits'][0]['_source']['case_id']
            # Extract number from CASE-001
            num = int(last_id.split('-')[1])
            return num
        else:
            return 0
    except Exception as e:
        # Index doesn't exist yet
        return 0

def get_unassigned_behaviors():
    """Get all behaviors without case_id assigned."""
    resp = es.search(
        index="argus-behaviors",
        body={
            "size": 1000,
            "query": {
                "bool": {
                    "must_not": {"exists": {"field": "case_id"}}
                }
            },
            "sort": [{"timestamp": {"order": "asc"}}]
        }
    )
    behaviors = [hit['_source'] for hit in resp['hits']['hits']]
    behavior_docs = [(hit['_id'], hit['_source']) for hit in resp['hits']['hits']]
    print(f"[INFO] Found {len(behaviors)} behaviors without case_id")
    return behavior_docs

def group_behaviors(behaviors):
    """
    Group behaviors by: same host + 30min window.
    
    REMOVED tactic constraint to allow multi-tactic incident chains like:
    DISCOVERY → EXECUTION → PERSISTENCE in one case.
    
    Prioritization now handled by severity multiplier at case level.
    
    Returns list of group dicts with items and metadata.
    """
    groups = []
    
    for doc_id, behavior in behaviors:
        ts = datetime.fromisoformat(behavior['timestamp'].replace('Z', '+00:00'))
        host = behavior.get('host', '').lower()
        
        # Try to add to existing group
        added = False
        for group in groups:
            # Same host and within 30min of latest event in group?
            if group['host'] == host and abs((ts - group['latest_ts']).total_seconds()) <= 1800:
                group['items'].append((doc_id, behavior))
                group['latest_ts'] = ts  # Update latest timestamp
                added = True
                break
        
        if not added:
            # Create new group with metadata
            groups.append({
                'items': [(doc_id, behavior)],
                'latest_ts': ts,
                'host': host
            })
    
    print(f"[INFO] Grouped {len(behaviors)} behaviors into {len(groups)} cases")
    return groups

def compute_blast_radius(behaviors):
    """Aggregate blast_radius from behavior list."""
    hosts = set()
    users = set()
    ips = set()
    processes = len(behaviors)  # Count behaviors as processes for now
    
    for doc_id, beh in behaviors:
        hosts.add(beh.get('host', '').lower())
        if 'user' in beh:
            users.add(beh['user'])
        if 'network' in beh and 'destination_ip' in beh['network']:
            ips.add(beh['network']['destination_ip'])
    
    return {
        "hosts_affected": len(hosts),
        "users_involved": len(users),
        "ips_contacted": len(ips),
        "processes_spawned": processes
    }

def compute_grouped_by(behaviors):
    """Determine grouping reason: shared_ip, shared_user, shared_host, time_window."""
    # Extract entities
    hosts = set()
    users = set()
    ips = set()
    timestamps = []
    
    for doc_id, beh in behaviors:
        hosts.add(beh.get('host', '').lower())
        if 'user' in beh:
            users.add(beh['user'])
        if 'network' in beh and 'destination_ip' in beh['network']:
            ips.add(beh['network']['destination_ip'])
        timestamps.append(datetime.fromisoformat(beh['timestamp'].replace('Z', '+00:00')))
    
    # Determine grouping reason
    grouped_by = {}
    
    # Shared host (always present since we group by host)
    if len(hosts) == 1:
        grouped_by['shared_host'] = list(hosts)[0]
    
    # Shared IP?
    if len(ips) == 1:
        grouped_by['shared_ip'] = list(ips)[0]
    
    # Shared user?
    if len(users) == 1:
        grouped_by['shared_user'] = list(users)[0]
    
    # Time window
    if timestamps:
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        window = f"{min_ts.strftime('%H:%M')}-{max_ts.strftime('%H:%M')}"
        grouped_by['time_window'] = window
    
    # Readable reason field for UI
    grouped_by['reason'] = f"{len(behaviors)} behaviors in 30min window"
    
    return grouped_by

def create_case(group, case_id):
    """Create one case document from a group of behaviors."""
    # Idempotency check - skip if case already exists
    if es.exists(index="argus-cases", id=case_id):
        print(f"[SKIP] {case_id} already exists")
        return case_id
    
    created_at = datetime.now(UTC).isoformat()
    
    # Extract items from group dict
    items = group['items']
    
    # Safe behavior_id extraction with fallback to doc_id
    behavior_ids = [beh.get('behavior_id', doc_id) for doc_id, beh in items]
    
    # Aggregate fields
    blast_radius = compute_blast_radius(items)
    grouped_by = compute_grouped_by(items)
    
    # Highest severity
    severities = [beh.get('severity', 'MEDIUM') for doc_id, beh in items]
    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    highest_severity = max(severities, key=lambda s: severity_order.get(s, 0))
    
    # Tactics seen
    tactics_seen = list(set([beh.get('tactic', '') for doc_id, beh in items if beh.get('tactic')]))
    
    # Risk score with severity multiplier
    base_score = sum([beh.get('priority_score', 50.0) for doc_id, beh in items])
    
    # Severity multiplier - intent weighs more than volume
    severity_weight = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }
    
    risk_score = base_score * severity_weight.get(highest_severity, 1)
    
    case_doc = {
        "case_id": case_id,
        "created_at": created_at,
        "status": "OPEN",
        "behavior_ids": behavior_ids,
        "behavior_count": len(behavior_ids),
        "grouped_by": grouped_by,
        "blast_radius": blast_radius,
        "highest_severity": highest_severity,
        "tactics_seen": tactics_seen,
        "risk_score": risk_score,
        "case_summary": ""  # Placeholder — Claude generates this later
    }
    
    # Write case to argus-cases
    es.index(index="argus-cases", id=case_id, document=case_doc)
    print(f"[CREATED] {case_id}: {len(behavior_ids)} behaviors, grouped_by={grouped_by}")
    print(f"[DEBUG] behaviors: {behavior_ids}")
    
    # Update behaviors with case_id
    for doc_id, beh in items:
        es.update(
            index="argus-behaviors",
            id=doc_id,
            body={"doc": {"case_id": case_id}}
        )
    
    return case_id

def run_once():
    """Single case building cycle - process all unassigned behaviors."""
    # Get behaviors without case_id
    behavior_docs = get_unassigned_behaviors()
    
    if not behavior_docs:
        print("[INFO] No unassigned behaviors.")
        return
    
    # Sort explicitly by timestamp to guarantee ordering
    behavior_docs.sort(key=lambda x: x[1]['timestamp'])
    
    # Group by host + tactic + 30min window
    groups = group_behaviors(behavior_docs)
    
    # Filter out groups with fewer than 3 behaviors
    MIN_CASE_SIZE = 3
    valid_groups = [g for g in groups if len(g['items']) >= MIN_CASE_SIZE]
    small_groups = [g for g in groups if len(g['items']) < MIN_CASE_SIZE]
    
    # Mark small groups as NOISE instead of discarding
    if small_groups:
        total_noise = sum(len(g['items']) for g in small_groups)
        for group in small_groups:
            for doc_id, beh in group['items']:
                es.update(
                    index="argus-behaviors",
                    id=doc_id,
                    body={"doc": {"case_id": "NOISE", "status": "NOISE"}}
                )
        print(f"[INFO] Marked {len(small_groups)} small groups ({total_noise} behaviors) as NOISE")
    
    # Get starting case number
    next_case_num = get_last_case_number()
    
    # Create one case per valid group with pre-generated IDs
    for i, group in enumerate(valid_groups):
        case_id = f"CASE-{next_case_num + i + 1:03d}"
        create_case(group, case_id)
    
    print(f"[DONE] Created {len(valid_groups)} cases")

def main():
    print("[START] Argus case_builder daemon (polling every 60s)")
    print("Press Ctrl+C to stop")
    
    while True:
        try:
            run_once()
        except KeyboardInterrupt:
            print("\n[STOP] case_builder daemon stopped")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
        
        time.sleep(60)

if __name__ == "__main__":
    main()
