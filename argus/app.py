"""
app.py - Argus FastAPI Backend

Serves:
- GET /cases - returns all cases sorted by risk_score desc
- Static files for frontend (index.html, etc.)

Run:
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from elasticsearch import Elasticsearch
import os

# ES connection - matches behavior_detector.py pattern
ES_URL  = os.environ.get("ES_URL", "http://192.168.100.143:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

es = Elasticsearch(
    ES_URL,
    basic_auth=(ES_USER, ES_PASS),
    request_timeout=30
)

app = FastAPI(title="Argus SOC Console")


@app.get("/api/cases")
async def get_cases():
    """
    Get all cases sorted by risk_score descending.
    
    Returns:
        {
          "cases": [
            {
              "case_id": "CASE-001",
              "status": "OPEN",
              "behavior_count": 80,
              "grouped_by": {...},
              "blast_radius": {...},
              "highest_severity": "LOW",
              "tactics_seen": ["DISCOVERY", "EXECUTION"],
              "risk_score": 4000.0,
              "case_summary": "",
              "created_at": "2026-04-15T..."
            },
            ...
          ]
        }
    """
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
        return {"ok": False, "error": str(e), "cases": []}


@app.get("/api/cases/{case_id}/behaviors")
async def get_case_behaviors(case_id: str):
    """
    Get all behaviors for a specific case, sorted by timestamp.
    
    Returns:
        {
          "behaviors": [
            {
              "behavior_id": "BEH-001",
              "timestamp": "2026-04-13T14:07:06.936Z",
              "host": "desktop-mm1rem9",
              "image": "whoami.exe",
              "command_line": "...",
              "tactic": "DISCOVERY",
              "mitre_technique": "T1033",
              "description": "...",
              "severity": "LOW",
              "status": "NEW"
            },
            ...
          ]
        }
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
        return {"ok": False, "error": str(e), "behaviors": []}


# Mount static files LAST to avoid intercepting API routes
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
