"""
app.py - Argus FastAPI Backend

Routes:
- GET /api/cases                        - all cases sorted by risk_score desc
- GET /api/cases/{case_id}/behaviors    - behaviors for a case (used by timeline)
- GET /api/cases/{case_id}/summary      - generate/return cached Claude case summary (4.5)
- GET /api/behaviors/{behavior_id}      - single behavior + parent case context
- GET /api/behaviors/{behavior_id}/process_tree  - adjacency JSON from raw Sysmon EID 1
- GET /api/behaviors/{behavior_id}/network_context - CL-1: Suricata cross-layer correlation
- PATCH /api/behaviors/{behavior_id}/status      - update behavior status
- GET /api/actions                      - analyst action audit trail
- POST /api/actions                     - write analyst action
- GET /api/hunt/templates               - list all hunt templates (metadata only)
- POST /api/hunt                        - execute a hunt template
- POST /api/hunt/raw_esql               - execute raw ES|QL (used by Create Behavior flow)
- POST /api/hunt/create_behavior        - create behavior doc from hunt result row (4.11)
- POST /api/hunt/copilot               - Claude interpretation of hunt results (4.10)
- POST /api/brief                       - generate Claude briefing for a behavior
- GET /api/brief/{behavior_id}          - fetch cached briefing from argus-briefings

Run:
    python -m uvicorn app:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from elasticsearch import Elasticsearch
from datetime import datetime
import os

ES_URL  = os.environ.get("ES_URL",  "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

es = Elasticsearch(
    ES_URL,
    basic_auth=(ES_USER, ES_PASS),
    request_timeout=30
)

app = FastAPI(title="Argus SOC Console")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# GET /api/cases
# ---------------------------------------------------------------------------
@app.get("/api/cases")
async def get_cases():
    """All cases sorted by risk_score descending."""
    try:
        resp = es.search(
            index="argus-cases",
            body={
                "size": 100,
                "sort": [{"risk_score": {"order": "desc"}}],
                "_source": [
                    "case_id", "status", "behavior_count",
                    "grouped_by", "blast_radius", "highest_severity",
                    "tactics_seen", "risk_score", "case_summary", "created_at"
                ]
            }
        )
        cases = [hit["_source"] for hit in resp["hits"]["hits"]]
        return {"ok": True, "cases": cases}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# GET /api/cases/{case_id}/behaviors
# Used by Screen 2 Panel A (timeline strip) — separate call from behavior context
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/behaviors")
async def get_case_behaviors(case_id: str):
    """
    All behaviors for a case, sorted by timestamp ascending.
    Frontend calls this separately to build the timeline strip.
    """
    try:
        resp = es.search(
            index="argus-behaviors",
            body={
                "size": 1000,
                "query": {"term": {"case_id.keyword": case_id}},
                "sort": [{"timestamp": {"order": "asc"}}],
                "_source": [
                    "behavior_id", "timestamp", "host", "image",
                    "command_line", "tactic", "mitre_technique",
                    "description", "severity", "status"
                ]
            }
        )
        behaviors = [hit["_source"] for hit in resp["hits"]["hits"]]
        return {"ok": True, "behaviors": behaviors}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# GET /api/cases/{case_id}/summary
# Generate 1-2 sentence Claude summary for a case card (task 4.5)
# Uses case metadata only — no behavior fetch needed. Caches result in ES.
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/summary")
async def get_case_summary(case_id: str):
    """
    Generate or return cached 1-2 sentence case summary for Screen 1 card.
    Uses case metadata (tactics, severity, count) — fast, no behavior fetch.
    """
    import httpx

    # Fetch case doc
    try:
        resp = es.search(
            index="argus-cases",
            body={
                "size": 1,
                "query": {"term": {"case_id.keyword": case_id}},
                "_source": [
                    "case_id", "tactics_seen", "highest_severity",
                    "behavior_count", "blast_radius", "grouped_by",
                    "risk_score", "case_summary"
                ]
            }
        )
        hits = resp["hits"]["hits"]
        if not hits:
            return {"ok": False, "error": f"Case {case_id} not found"}
        c = hits[0]["_source"]
    except Exception as e:
        return {"ok": False, "error": str(e)}

    # Return cached summary if already generated
    if c.get("case_summary") and len(c["case_summary"]) > 10:
        return {"ok": True, "summary": c["case_summary"], "cached": True}

    # Build prompt from case metadata only
    tactics  = ", ".join(c.get("tactics_seen", []))
    severity = c.get("highest_severity", "unknown")
    count    = c.get("behavior_count", 0)
    host     = c.get("grouped_by", {}).get("shared_host", "unknown host")
    window   = c.get("grouped_by", {}).get("time_window", "unknown window")

    prompt = f"""You are a SOC analyst assistant. Write exactly 1-2 sentences summarizing this security case for a triage queue. Be specific and direct. No fluff.

Case data:
- Host: {host}
- Time window: {window}
- Tactics observed: {tactics}
- Highest severity: {severity}
- Total behaviors: {count}

Write 1-2 sentences only. Start with what happened, end with why it matters. No bullet points. No headers. No preamble."""

    CLAUDE_API_KEY = os.environ.get("CLAUDE_API_KEY", "")
    if not CLAUDE_API_KEY:
        return {"ok": False, "error": "CLAUDE_API_KEY not set"}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key":         CLAUDE_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type":      "application/json"
                },
                json={
                    "model":      "claude-haiku-4-5-20251001",
                    "max_tokens": 120,
                    "messages":   [{"role": "user", "content": prompt}]
                }
            )
            r.raise_for_status()
            summary = r.json()["content"][0]["text"].strip()
    except Exception as e:
        return {"ok": False, "error": f"Claude API failed: {str(e)}"}

    # Write back to case doc so next load is instant (cached)
    try:
        es.update_by_query(
            index="argus-cases",
            body={
                "script": {
                    "source": "ctx._source.case_summary = params.summary",
                    "params": {"summary": summary}
                },
                "query": {"term": {"case_id.keyword": case_id}}
            }
        )
    except Exception:
        pass  # non-fatal — still return the summary

    return {"ok": True, "summary": summary, "cached": False}


# ---------------------------------------------------------------------------
# GET /api/behaviors/{behavior_id}
# Primary context load for Screen 2
# ---------------------------------------------------------------------------
@app.get("/api/behaviors/{behavior_id}")
async def get_behavior(behavior_id: str):
    """
    Single behavior + parent case metadata.

    Frontend uses this for:
    - behavior detail (tactic, severity, image, command_line, timestamp, host)
    - case_id to make the separate /api/cases/{id}/behaviors call for timeline

    NOTE: Process tree comes from /api/behaviors/{id}/process_tree
    Raw Sysmon logs are the source for tree, not argus-behaviors.
    """
    try:
        resp = es.search(
            index="argus-behaviors",
            body={
                "size": 1,
                "query": {"term": {"behavior_id.keyword": behavior_id}}
            }
        )
        hits = resp["hits"]["hits"]
        if not hits:
            raise HTTPException(status_code=404, detail=f"Behavior {behavior_id} not found")

        behavior = hits[0]["_source"]

        # Fetch parent case — skip if NOISE (no real case document exists)
        case = None
        case_id = behavior.get("case_id")
        if case_id and case_id != "NOISE":
            case_resp = es.search(
                index="argus-cases",
                body={
                    "size": 1,
                    "query": {"term": {"case_id.keyword": case_id}},
                    "_source": [
                        "case_id", "status", "behavior_count", "grouped_by",
                        "blast_radius", "highest_severity", "tactics_seen",
                        "risk_score", "case_summary", "created_at"
                    ]
                }
            )
            case_hits = case_resp["hits"]["hits"]
            if case_hits:
                case = case_hits[0]["_source"]

        return {"ok": True, "behavior": behavior, "case": case}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# GET /api/behaviors/{behavior_id}/process_tree
# Queries raw Sysmon EID 1 — NOT argus-behaviors
# Source: logs-winlog.winlog-default
# ---------------------------------------------------------------------------
@app.get("/api/behaviors/{behavior_id}/process_tree")
async def get_process_tree(behavior_id: str):
    """
    Build process tree for a behavior.

    Flow:
    1. Fetch behavior to get timestamp + host
    2. Query raw Sysmon EID 1 in +-15min window on that host
    3. Build adjacency JSON (nodes + links)
    4. Score nodes: grey=normal, orange=suspicious, red=malicious
    """
    from process_tree_builder import build_process_tree

    # Step 1 — get timestamp + host from behavior doc
    try:
        resp = es.search(
            index="argus-behaviors",
            body={
                "size": 1,
                "query": {"term": {"behavior_id.keyword": behavior_id}},
                "_source": ["timestamp", "host", "image"]
            }
        )
        hits = resp["hits"]["hits"]
        if not hits:
            raise HTTPException(status_code=404, detail=f"Behavior {behavior_id} not found")

        src       = hits[0]["_source"]
        timestamp = src.get("timestamp")
        host      = src.get("host")
        image     = src.get("image")  # for behavior_pid identification in tree

        if not timestamp or not host:
            raise HTTPException(status_code=422, detail="Behavior missing timestamp or host")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Step 2 — build tree from raw logs
    try:
        tree = build_process_tree(
            behavior_id=behavior_id,
            timestamp=timestamp,
            host=host,
            behavior_image=image
        )
        return {"ok": True, **tree}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Tree build failed: {str(e)}")


# ---------------------------------------------------------------------------
# GET /api/behaviors/{behavior_id}/network_context
# CL-1 — Cross-layer correlation: Sysmon behavior + Suricata NDR
#
# Field facts (confirmed 2026-05-16 against filebeat-7.14.0-2026.05.16):
#   - Suricata EVE is ingested raw (module not loaded), fields are FLAT not nested
#   - IP fields:  src_ip.keyword, dest_ip.keyword, flow.src_ip.keyword, flow.dest_ip.keyword
#   - Time field: timestamp (Suricata event time, mapped as date) — NOT @timestamp (ingest time)
#   - Event types present: alert, http, fileinfo
#   - Alert fields: alert.signature, alert.signature_id, alert.severity, alert.category
#   - Victim IP filter: 10.0.20.10 (DESKTOP-MM1REM9) via src/dest, not host.name
#   - Window: +-15min around behavior timestamp (consistent with process_tree_builder.py)
#   - Index: filebeat-* (old indices have broken text mappings, query still works on new)
#   - Empty result is valid data: return has_network_data=False, never raise error
# ---------------------------------------------------------------------------
@app.get("/api/behaviors/{behavior_id}/network_context")
async def get_network_context(behavior_id: str):
    """
    Cross-layer correlation for a behavior.

    Fetches Suricata EVE events in a +-15min window around the behavior timestamp,
    filtered to victim IP (10.0.20.10) via src_ip, dest_ip, flow.src_ip, flow.dest_ip.

    Returns:
      has_network_data: bool
      network_events: list of http/fileinfo events (url, dest_ip, dest_port, timestamp)
      alerts:  list of Suricata alert events (signature, signature_id, severity, src/dest)
      summary: returned, total_hits, alert_count, network_event_count, unique_ips
    """
    from datetime import timedelta

    # Step 1: fetch behavior timestamp + host
    try:
        resp = es.search(
            index="argus-behaviors",
            body={
                "size": 1,
                "query": {"term": {"behavior_id.keyword": behavior_id}},
                "_source": ["timestamp", "host"]
            }
        )
        hits = resp["hits"]["hits"]
        if not hits:
            raise HTTPException(status_code=404, detail=f"Behavior {behavior_id} not found")

        src = hits[0]["_source"]
        behavior_ts = src.get("timestamp")
        if not behavior_ts:
            raise HTTPException(status_code=422, detail="Behavior missing timestamp")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Step 2: build +-15min window around behavior timestamp
    try:
        # Parse ISO timestamp — handle both Z and +00:00 suffixes
        ts_clean = behavior_ts.replace("Z", "+00:00")
        center   = datetime.fromisoformat(ts_clean)
        start_ts = (center - timedelta(minutes=15)).isoformat()
        end_ts   = (center + timedelta(minutes=15)).isoformat()
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Could not parse behavior timestamp: {str(e)}")

    # Step 3: query Suricata data from filebeat-*
    # Use Suricata `timestamp` field (real event time), NOT `@timestamp` (Filebeat ingest time)
    # Both top-level and flow.* IPs required — some events only have context inside flow
    VICTIM_IP = "10.0.20.10"

    try:
        ndr_resp = es.search(
            index="filebeat-*",
            body={
                "size": 200,
                "track_total_hits": True,
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"src_ip.keyword":       VICTIM_IP}},
                            {"term": {"dest_ip.keyword":      VICTIM_IP}},
                            {"term": {"flow.src_ip.keyword":  VICTIM_IP}},
                            {"term": {"flow.dest_ip.keyword": VICTIM_IP}}
                        ],
                        "minimum_should_match": 1,
                        "filter": [
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_ts,
                                        "lte": end_ts
                                    }
                                }
                            },
                            {
                                "terms": {
                                    "event_type.keyword": ["alert", "http", "fileinfo"]
                                }
                            }
                        ]
                    }
                },
                "sort": [{"timestamp": {"order": "asc"}}],
                "_source": [
                    "timestamp", "event_type",
                    "src_ip", "dest_ip", "src_port", "dest_port",
                    "proto", "flow",
                    "alert.signature", "alert.signature_id",
                    "alert.severity", "alert.category", "alert.action",
                    "http.hostname", "http.url", "http.method",
                    "http.status", "http.http_user_agent"
                ]
            }
        )
    except Exception as e:
        # Non-fatal: old filebeat indices may error on some fields
        # Return empty rather than 500 so the UI degrades gracefully
        return {
            "ok":               True,
            "has_network_data": False,
            "network_events":   [],
            "alerts":           [],
            "summary": {
                "returned":             0,
                "total_hits":           0,
                "alert_count":          0,
                "network_event_count":  0,
                "unique_ips":           []
            },
            "window": {"start": start_ts, "end": end_ts},
            "error":  str(e)
        }

    # Step 4: separate and normalise results by event_type
    raw_hits = ndr_resp["hits"]["hits"]

    alerts         = []
    network_events = []
    unique_ips     = set()

    for h in raw_hits:
        s  = h["_source"]
        et = s.get("event_type", "")

        # Collect all non-victim IPs seen in this event
        for ip_field in [s.get("dest_ip"), s.get("src_ip")]:
            if ip_field and ip_field != VICTIM_IP:
                unique_ips.add(ip_field)

        if et == "alert":
            alerts.append({
                "timestamp":    s.get("timestamp"),
                "event_type":   "alert",
                "src_ip":       s.get("src_ip"),
                "dest_ip":      s.get("dest_ip"),
                "src_port":     s.get("src_port"),
                "dest_port":    s.get("dest_port"),
                "proto":        s.get("proto"),
                "signature":    s.get("alert", {}).get("signature"),
                "signature_id": s.get("alert", {}).get("signature_id"),
                "severity":     s.get("alert", {}).get("severity"),
                "category":     s.get("alert", {}).get("category"),
                "action":       s.get("alert", {}).get("action"),
            })

        elif et in ("http", "fileinfo"):
            http_obj = s.get("http", {})
            if not isinstance(http_obj, dict):
                http_obj = {}
            network_events.append({
                "timestamp":  s.get("timestamp"),
                "event_type": et,
                "src_ip":     s.get("src_ip") or s.get("flow", {}).get("src_ip"),
                "dest_ip":    s.get("dest_ip") or s.get("flow", {}).get("dest_ip"),
                "src_port":   s.get("src_port"),
                "dest_port":  s.get("dest_port"),
                "proto":      s.get("proto"),
                "url":        http_obj.get("url"),
                "hostname":   http_obj.get("hostname"),
                "method":     http_obj.get("method"),
                "status":     http_obj.get("status"),
                "user_agent": http_obj.get("http_user_agent"),
            })

    has_data = len(alerts) > 0 or len(network_events) > 0

    return {
        "ok":               True,
        "has_network_data": has_data,
        "network_events":   network_events,
        "alerts":           alerts,
        "summary": {
            "returned":            len(raw_hits),
            "total_hits":          ndr_resp["hits"]["total"]["value"],
            "alert_count":         len(alerts),
            "network_event_count": len(network_events),
            "unique_ips":          list(unique_ips)
        },
        "window": {
            "start": start_ts,
            "end":   end_ts
        }
    }


# ---------------------------------------------------------------------------
# PATCH /api/behaviors/{behavior_id}/status
# Panel F — update behavior status in argus-behaviors
# ---------------------------------------------------------------------------
@app.patch("/api/behaviors/{behavior_id}/status")
async def update_behavior_status(behavior_id: str, payload: dict):
    try:
        new_status = payload.get("status")
        if not new_status:
            return {"ok": False, "error": "Missing status"}

        resp = es.update_by_query(
            index="argus-behaviors",
            body={
                "script": {
                    "source": "ctx._source.status = params.status",
                    "params": {"status": new_status}
                },
                "query": {
                    "term": {"behavior_id.keyword": behavior_id}
                }
            }
        )

        updated = resp.get("updated", 0)
        if updated == 0:
            return {"ok": False, "error": "Behavior not found or not updated"}

        return {"ok": True}

    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# GET /api/actions
# Screen 3 — Actions Log, sorted by timestamp desc
# ---------------------------------------------------------------------------
@app.get("/api/actions")
async def get_actions(limit: int = 200):
    """All analyst actions, newest first. Used by Screen 3 Actions Log."""
    try:
        resp = es.search(
            index="argus-actions",
            body={
                "size": limit,
                "sort": [
                    {"timestamp":           {"order": "desc"}},
                    {"behavior_id.keyword": {"order": "desc"}}  # stable tiebreak
                ],
                "_source": [
                    "behavior_id", "case_id", "action", "note", "actor", "timestamp"
                ]
            }
        )
        actions = [hit["_source"] for hit in resp["hits"]["hits"]]
        return {
            "ok":      True,
            "actions": actions,
            "total":   resp["hits"]["total"]["value"],
            "limit":   limit,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# POST /api/actions
# Panel F — write analyst action to argus-actions index (audit trail)
# ---------------------------------------------------------------------------
@app.post("/api/actions")
async def create_action(payload: dict):
    try:
        allowed = {"ESCALATE", "BLOCK_IP", "NOTE"}
        if payload.get("action") not in allowed:
            return {"ok": False, "error": f"Invalid action. Must be one of: {', '.join(allowed)}"}

        doc = {
            "behavior_id": payload.get("behavior_id"),
            "case_id":     payload.get("case_id"),
            "action":      payload.get("action"),
            "note":        payload.get("note"),
            "actor":       payload.get("actor", "analyst"),
            "timestamp":   datetime.utcnow().isoformat() + "Z",
        }

        resp = es.index(index="argus-actions", document=doc)
        if resp.get("result") not in ("created", "updated"):
            return {"ok": False, "error": f"Unexpected ES result: {resp.get('result')}"}

        return {"ok": True}

    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# GET /api/hunt/templates
# Screen 4 — returns template catalogue (metadata only, no execution)
# ---------------------------------------------------------------------------
@app.get("/api/hunt/templates")
async def get_hunt_templates():
    """All hunt template metadata. Used by Screen 4 sidebar to populate template list."""
    from hunt_engine import list_templates
    return {"ok": True, "templates": list_templates()}


# ---------------------------------------------------------------------------
# POST /api/hunt
# Screen 4 — execute a hunt template with analyst-supplied params
# Body: { "template_id": "HT-01", "params": { "host": "...", "hours": 24 } }
# ---------------------------------------------------------------------------
@app.post("/api/hunt")
async def run_hunt(payload: dict):
    """
    Execute a hunt template against raw Sysmon telemetry.

    Returns columns + rows for the results table, plus the rendered ES|QL
    query string so the analyst can see exactly what ran.
    """
    from hunt_engine import run_hunt as _run_hunt

    template_id = payload.get("template_id")
    params      = payload.get("params", {})

    if not template_id:
        return {"ok": False, "error": "Missing template_id"}

    result = _run_hunt(template_id, **params)

    if not isinstance(result, dict) or "ok" not in result:
        return {"ok": False, "error": "Invalid engine response"}

    return result


# ---------------------------------------------------------------------------
# POST /api/hunt/raw_esql
# Screen 4 internal — executes a raw ES|QL query string directly.
# Used by Create Behavior flow to fetch real event context for a hunt row.
# ---------------------------------------------------------------------------
@app.post("/api/hunt/raw_esql")
async def hunt_raw_esql(payload: dict):
    """Execute a raw ES|QL query. Used internally by Create Behavior to fetch real event context."""
    query = payload.get("query", "").strip()
    if not query:
        return {"ok": False, "error": "Missing query"}
    try:
        resp    = es.esql.query(body={"query": query})
        columns = resp.get("columns", [])
        rows    = resp.get("values",  [])
        return {"ok": True, "columns": columns, "rows": rows, "total": len(rows)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# POST /api/hunt/create_behavior
# Screen 4 — create a behavior document from a hunt result row (4.11)
# ---------------------------------------------------------------------------
@app.post("/api/hunt/create_behavior")
async def hunt_create_behavior(payload: dict):
    """
    Create a behavior from a hunt result row.
    Fields: description, tactic, severity, host, hunt_template, hunt_context, status
    """
    try:
        required = ["description", "tactic", "severity"]
        for f in required:
            if not payload.get(f):
                return {"ok": False, "error": f"Missing required field: {f}"}

        import hashlib, time
        raw_id      = hashlib.md5(
            f"{payload.get('description')}{payload.get('host','')}{time.time()}".encode()
        ).hexdigest()[:8].upper()
        behavior_id = f"BEH-{raw_id}"

        doc = {
            "behavior_id":   behavior_id,
            "description":   payload.get("description"),
            "tactic":        payload.get("tactic"),
            "severity":      payload.get("severity"),
            "host":          payload.get("host"),
            "status":        payload.get("status", "NEW"),
            "source":        "HUNT",
            "hunt_template": payload.get("hunt_template"),
            "hunt_context":  payload.get("hunt_context"),
            "timestamp":     datetime.utcnow().isoformat() + "Z",
            "fire_reasons":  [f"Hunt result from {payload.get('hunt_template', 'unknown')}"],
        }

        resp = es.index(index="argus-behaviors", document=doc)
        if resp.get("result") not in ("created", "updated"):
            return {"ok": False, "error": f"Unexpected ES result: {resp.get('result')}"}

        return {"ok": True, "behavior_id": behavior_id}

    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# POST /api/brief
# Investigation screen — generate Claude AI briefing for a behavior.
# Narration only. Claude never scores, labels, or classifies.
# Caches result in argus-briefings index so repeat loads are instant.
# ---------------------------------------------------------------------------
@app.post("/api/brief")
async def generate_brief(payload: dict):
    """
    Generate an AI briefing for a behavior using Claude Haiku.
    Returns: summary (2-3 sentences), next_steps (3 items), escalate (bool).
    Stores result in argus-briefings for caching.
    """
    import httpx, json as _json

    behavior_id = payload.get("behavior_id")
    if not behavior_id:
        return {"ok": False, "error": "Missing behavior_id"}

    # Fetch behavior doc from ES
    try:
        resp = es.search(
            index="argus-behaviors",
            body={
                "size": 1,
                "query": {"term": {"behavior_id.keyword": behavior_id}}
            }
        )
        hits = resp["hits"]["hits"]
        if not hits:
            return {"ok": False, "error": f"Behavior {behavior_id} not found"}
        b = hits[0]["_source"]
    except Exception as e:
        return {"ok": False, "error": f"ES fetch failed: {str(e)}"}

    # Build prompt — deterministic engine fields only, no scoring
    prompt = f"""You are an analyst assistant inside a SOC investigation console called Argus.
A detection engine has flagged a suspicious behavior. Explain it clearly to a SOC analyst.

Behavior details:
- Description: {b.get('description', 'unknown')}
- Process: {b.get('image', 'unknown')}
- Command line: {b.get('command_line', 'none')}
- Tactic: {b.get('tactic', 'unknown')}
- MITRE technique: {b.get('mitre_technique', 'unknown')}
- Severity: {b.get('severity', 'unknown')}
- Host: {b.get('host', 'unknown')}
- Timestamp: {b.get('timestamp', 'unknown')}
- Fire reasons: {', '.join(b.get('fire_reasons', []))}

Respond in exactly this JSON format with no extra text, no markdown, no backticks:
{{
  "summary": "2-3 sentence plain English explanation of what happened and why it is suspicious",
  "next_steps": [
    "First concrete investigative action the analyst should take",
    "Second concrete investigative action",
    "Third concrete investigative action"
  ],
  "escalate": true
}}

escalate should be true if severity is HIGH or CRITICAL, false otherwise."""

    CLAUDE_API_KEY = os.environ.get("CLAUDE_API_KEY", "")
    if not CLAUDE_API_KEY:
        return {"ok": False, "error": "CLAUDE_API_KEY not set in environment"}

    # Call Claude Haiku — fast and cheap for narration
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key":            CLAUDE_API_KEY,
                    "anthropic-version":    "2023-06-01",
                    "content-type":         "application/json"
                },
                json={
                    "model":      "claude-haiku-4-5-20251001",
                    "max_tokens": 500,
                    "messages":   [{"role": "user", "content": prompt}]
                }
            )
            r.raise_for_status()
            raw = r.json()["content"][0]["text"].strip()
    except Exception as e:
        return {"ok": False, "error": f"Claude API failed: {str(e)}"}

    # Parse JSON response
    try:
        briefing = _json.loads(raw)
    except Exception:
        # Haiku occasionally wraps in backticks despite instructions — strip and retry
        try:
            clean    = raw.replace("```json", "").replace("```", "").strip()
            briefing = _json.loads(clean)
        except Exception:
            return {"ok": False, "error": "Claude response was not valid JSON", "raw": raw}

    # Cache in argus-briefings — failure is non-fatal, still return briefing
    try:
        doc = {
            "behavior_id":  behavior_id,
            "summary":      briefing.get("summary"),
            "next_steps":   briefing.get("next_steps", []),
            "escalate":     briefing.get("escalate", False),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "model":        "claude-haiku-4-5-20251001"
        }
        es.index(index="argus-briefings", document=doc)
    except Exception:
        pass

    return {"ok": True, "briefing": briefing}


# ---------------------------------------------------------------------------
# GET /api/brief/{behavior_id}
# Fetch cached briefing — avoids re-calling Claude on page reload
# ---------------------------------------------------------------------------
@app.get("/api/brief/{behavior_id}")
async def get_brief(behavior_id: str):
    """Fetch the most recent cached Claude briefing from argus-briefings."""
    try:
        resp = es.search(
            index="argus-briefings",
            body={
                "size": 1,
                "query": {"term": {"behavior_id.keyword": behavior_id}},
                "sort": [{"generated_at": {"order": "desc"}}]
            }
        )
        hits = resp["hits"]["hits"]
        if not hits:
            return {"ok": False, "error": "No briefing cached"}
        return {"ok": True, "briefing": hits[0]["_source"]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# POST /api/hunt/copilot
# Screen 4 — Claude co-pilot interpretation of hunt results (4.10)
# Ephemeral: no ES persistence. Cached client-side in LAST_RESULT.copilot.
# ---------------------------------------------------------------------------

COPILOT_PROMPT_SYSTEM = """You are a detection engineer co-pilot embedded in a SOC investigation console.
You receive hunt results from Elasticsearch ES|QL queries and provide concise, accurate analysis.
Respond ONLY with valid JSON matching this exact schema — no preamble, no markdown fences:
{
  "summary": "2-3 sentence interpretation of what the results show",
  "findings": ["finding 1", "finding 2"],
  "mitre_tags": ["T1059.001"],
  "recommended_actions": ["action 1", "action 2"],
  "limitations": ["Interpretation based only on returned rows, not full telemetry corpus"]
}
Rules:
- summary must state what the hunt found, not what the hunt template does
- findings must reference specific values from the rows where possible
- mitre_tags: only include if genuinely supported by the data; empty array is fine
- recommended_actions: concrete analyst next steps, not generic advice
- limitations: always include the scope limitation sentence verbatim as shown above
- Never claim certainty about attacker intent from rows alone"""


@app.post("/api/hunt/copilot")
async def hunt_copilot(payload: dict):
    """
    Generate Claude co-pilot interpretation of hunt results.
    Receives compact payload: template metadata + columns + up to 20 preview rows.
    Returns structured JSON: summary, findings, mitre_tags, recommended_actions, limitations.
    No ES write — ephemeral, cached client-side only.
    """
    import httpx, json as _json

    api_key = os.environ.get("CLAUDE_API_KEY", "")
    if not api_key:
        return {"ok": False, "error": "CLAUDE_API_KEY not set"}

    template_id          = payload.get("template_id", "unknown")
    template_name        = payload.get("template_name", template_id)
    template_description = payload.get("template_description", "")
    query                = payload.get("query", "")
    columns              = payload.get("columns", [])
    total_rows           = payload.get("total_rows", 0)
    preview_rows         = payload.get("preview_rows", [])
    suspicious_count     = payload.get("suspicious_row_count", 0)

    # Build compact readable row preview — cap at 20 rows
    # Sanitize newlines before truncation so large command lines don't break prompt structure
    rows_text = ""
    if preview_rows and columns:
        rows_text = " | ".join(str(c) for c in columns) + "\n"
        for row in preview_rows[:20]:
            rows_text += " | ".join(
                str(v).replace("\n", " ").replace("\r", " ")[:120]
                if v is not None else "null"
                for v in row
            ) + "\n"

    user_prompt = f"""Hunt template: {template_name} ({template_id})
Template purpose: {template_description}

ES|QL query executed:
{query}

Results: {total_rows} rows ({suspicious_count} flagged suspicious by client heuristics)
Columns: {', '.join(str(c) for c in columns)}

Row preview (up to 20 rows):
{rows_text if rows_text else '(no rows)'}

Interpret these results for a SOC analyst."""

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key":         api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type":      "application/json",
                },
                json={
                    "model":      "claude-haiku-4-5-20251001",
                    "max_tokens": 800,
                    "system":     COPILOT_PROMPT_SYSTEM,
                    "messages":   [{"role": "user", "content": user_prompt}],
                },
            )
        resp.raise_for_status()
        raw = resp.json()["content"][0]["text"].strip()

        # Two-pass JSON parse — Haiku occasionally wraps in backticks despite instructions (Lesson 167)
        try:
            copilot = _json.loads(raw)
        except _json.JSONDecodeError:
            clean   = raw.replace("```json", "").replace("```", "").strip()
            copilot = _json.loads(clean)

        # Enforce limitations field — always present regardless of model output
        if not copilot.get("limitations"):
            copilot["limitations"] = [
                "Interpretation based only on returned rows, not full telemetry corpus"
            ]

        return {"ok": True, "copilot": copilot}

    except httpx.HTTPStatusError as e:
        return {"ok": False, "error": f"Claude API HTTP {e.response.status_code}"}
    except _json.JSONDecodeError as e:
        return {"ok": False, "error": f"Claude returned non-JSON: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
