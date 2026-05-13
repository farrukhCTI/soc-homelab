"""
process_tree_builder.py - Argus Week 3

Four stages only:
  1. fetch_events()       - query EID 1, ±15min window, host filter
  2. build_pid_map()      - extract fields, normalize pid/ppid to str
  3. link_parent_child()  - build nodes[] and edges[]
  4. select_root()        - node whose ppid is not in pid map

Output contract (locked):
{
  "nodes": [{"id": str, "name": str, "full_path": str, "cmd": str, "ts": str, "ppid": str}],
  "edges": [{"source": str, "target": str}],
  "root": str | null,
  "node_count": int,
  "behavior_pid": str | null,
  "window": {"start": str, "end": str}
}

Empty tree is valid — returns same shape with empty arrays, no exception.
ES query failure raises — not masked as empty tree.
All timestamps treated as UTC. No local conversion.
Timestamp parse failure raises ValueError — no silent fallback.
"""

import os
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch

ES_URL  = os.environ.get("ES_URL",  "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), request_timeout=30)

EMPTY_TREE = {
    "nodes": [],
    "edges": [],
    "root": None,
    "node_count": 0,
    "behavior_pid": None,
    "window": {"start": None, "end": None}
}


def _parse_utc(ts_str: str) -> datetime:
    """Parse UTC ISO8601 string to aware datetime. Raises ValueError on failure."""
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValueError(f"Invalid timestamp '{ts_str}': {exc}")


def _fmt_utc(dt: datetime) -> str:
    """Format aware datetime to UTC ISO8601 with milliseconds."""
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Stage 1 — fetch raw EID 1 events
# ---------------------------------------------------------------------------
def fetch_events(timestamp: str, host: str) -> tuple:
    """
    Query Sysmon EID 1 events in ±15min window on the given host.
    Returns (hits, window_start, window_end).
    Empty hits list is valid — not an error.

    Raises:
      ValueError  — unparseable timestamp (fail fast, no silent shift)
      Exception   — ES query failure (NOT masked as empty tree)

    host.name uses term filter (exact, case-sensitive — must be lowercase).
    size: 200 — accuracy over performance.
    """
    ts = _parse_utc(timestamp)  # raises ValueError if bad

    window_start = _fmt_utc(ts - timedelta(minutes=15))
    window_end   = _fmt_utc(ts + timedelta(minutes=15))

    # ES query failure propagates up — caller decides how to handle
    resp = es.search(
        index="logs-winlog.winlog-default",
        body={
            "size": 200,
            "query": {
                "bool": {
                    "must": [
                        {"term":  {"event.code": "1"}},
                        {"term":  {"host.name.keyword": host}},
                        {"range": {"@timestamp": {
                            "gte": window_start,
                            "lte": window_end
                        }}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "asc"}}],
            "_source": [
                "winlog.event_data.Image",
                "winlog.event_data.CommandLine",
                "winlog.event_data.ProcessId",
                "winlog.event_data.ParentProcessId",
                "winlog.event_data.ParentImage",
                "@timestamp"
            ]
        }
    )
    return resp["hits"]["hits"], window_start, window_end


# ---------------------------------------------------------------------------
# Stage 2 — build pid map from raw hits
# ---------------------------------------------------------------------------
def build_pid_map(hits: list) -> dict:
    """
    Extract fields from each hit. Normalize pid/ppid to str.
    Field path: hit["_source"]["winlog"]["event_data"]["ProcessId"]
    Returns {pid_str: {id, name, full_path, cmd, ts, ppid, ts_dt}} dict.
    Deduplicates by pid — first occurrence wins (hits sorted asc by timestamp).
    cmd stored full — truncate in frontend, not here.
    ts_dt stored as parsed datetime for timestamp comparisons (not exposed in output).
    """
    pid_map = {}

    for hit in hits:
        src = hit.get("_source", {})
        ed  = src.get("winlog", {}).get("event_data", {})

        raw_image = ed.get("Image") or "unknown"
        name      = raw_image.split("\\")[-1] if "\\" in raw_image else raw_image
        pid       = str(ed.get("ProcessId") or "0")
        ppid      = str(ed.get("ParentProcessId") or "0")
        cmd       = ed.get("CommandLine") or ""
        ts_str    = src.get("@timestamp", "")

        if not pid or pid == "0":
            continue

        if pid in pid_map:
            continue  # dedup — first occurrence = earliest by asc sort

        # Parse ts_dt for comparisons — fall back to epoch if unparseable
        try:
            ts_dt = _parse_utc(ts_str)
        except ValueError:
            ts_dt = datetime.min.replace(tzinfo=timezone.utc)

        pid_map[pid] = {
            "id":        pid,
            "name":      name,
            "full_path": raw_image,
            "cmd":       cmd,
            "ts":        ts_str,
            "ts_dt":     ts_dt,   # internal — stripped before API response
            "ppid":      ppid
        }

    return pid_map


# ---------------------------------------------------------------------------
# Stage 3 — build nodes and edges
# ---------------------------------------------------------------------------
def link_parent_child(pid_map: dict) -> tuple:
    """
    Build nodes list and edges list from pid_map.
    Edge exists only if ppid is in pid_map (parent visible in window).
    Returns (nodes, edges).
    """
    nodes = list(pid_map.values())
    edges = []

    for node in nodes:
        ppid = node["ppid"]
        pid  = node["id"]
        if ppid and ppid in pid_map and ppid != pid:
            edges.append({"source": ppid, "target": pid})

    return nodes, edges


# ---------------------------------------------------------------------------
# Stage 4 — select root
# ---------------------------------------------------------------------------
def select_root(nodes: list, pid_map: dict) -> str | None:
    """
    Root is the node whose ppid is NOT in pid_map.
    If multiple qualify, pick earliest by parsed datetime (not string sort).
    If all nodes have visible parents, pick earliest as fallback.
    """
    if not nodes:
        return None

    candidates = [n for n in nodes if n["ppid"] not in pid_map]
    if not candidates:
        candidates = list(nodes)

    candidates.sort(key=lambda n: n["ts_dt"])
    return candidates[0]["id"]


# ---------------------------------------------------------------------------
# Internal helper — strip ts_dt before returning to API
# ---------------------------------------------------------------------------
def _strip_internal_fields(nodes: list) -> list:
    """Remove ts_dt (internal comparison field) from node dicts before API response."""
    return [{k: v for k, v in n.items() if k != "ts_dt"} for n in nodes]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def build_process_tree(behavior_id: str, timestamp: str, host: str,
                       behavior_image: str = None) -> dict:
    """
    Build process tree for a behavior. Returns locked output contract.
    Empty tree (no events in window) is valid — returns EMPTY_TREE shape.
    ES failure raises — not swallowed.

    behavior_image: pass src.get("image") from behavior doc.
                    Used to identify behavior_pid by name + closest timestamp.
                    Falls back to root if not matched.
    """
    # Stage 1 — may raise ValueError (bad ts) or ES exception
    hits, window_start, window_end = fetch_events(timestamp, host)

    if not hits:
        result = dict(EMPTY_TREE)
        result["window"] = {"start": window_start, "end": window_end}
        return result

    # Stage 2
    pid_map = build_pid_map(hits)

    if not pid_map:
        result = dict(EMPTY_TREE)
        result["window"] = {"start": window_start, "end": window_end}
        return result

    # Stage 3
    nodes, edges = link_parent_child(pid_map)

    # Stage 4
    root = select_root(nodes, pid_map)

    # behavior_pid: match by name AND closest timestamp to behavior timestamp
    # Multiple cmd.exe/powershell.exe can exist — timestamp proximity breaks tie
    behavior_pid = root  # default fallback
    if behavior_image:
        bname = behavior_image.split("\\")[-1].lower()
        try:
            behavior_ts = _parse_utc(timestamp)
        except ValueError:
            behavior_ts = None

        candidates = [n for n in nodes if n["name"].lower() == bname]
        if candidates and behavior_ts:
            # Pick candidate with timestamp closest to behavior timestamp
            candidates.sort(key=lambda n: abs((n["ts_dt"] - behavior_ts).total_seconds()))
            behavior_pid = candidates[0]["id"]
        elif candidates:
            behavior_pid = candidates[0]["id"]

    # Strip internal ts_dt before returning
    clean_nodes = _strip_internal_fields(nodes)

    return {
        "nodes":        clean_nodes,
        "edges":        edges,
        "root":         root,
        "node_count":   len(clean_nodes),
        "behavior_pid": behavior_pid,
        "window":       {"start": window_start, "end": window_end}
    }
