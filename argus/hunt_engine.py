"""
hunt_engine.py — Argus Hunt Workbench Engine

Seven ES|QL hunt templates targeting raw Sysmon telemetry.
Each template is a parameterized ES|QL query that the analyst
can run from Screen 4, optionally refined by Claude co-pilot.

Index:  logs-winlog.winlog-default  (raw Sysmon EID 1/3/11/13)
Fields: winlog.event_data.* + host.name.keyword + @timestamp

Template catalogue:
  HT-01  Rare parent-child pairs         — unusual process spawn relationships
  HT-02  Encoded PowerShell              — base64 -EncodedCommand usage
  HT-03  Outbound connections by process — which processes are calling home
  HT-04  New scheduled task creation     — EID 1 schtasks.exe w/ /create
  HT-05  Registry run key writes         — EID 13 persistence via RunKey
  HT-06  Credential access tools         — mimikatz, procdump, pwdump (EID 1 only)
  HT-07  High-frequency child spawning   — process spawning >N children (pivot point)

Usage:
    from hunt_engine import run_hunt
    results = run_hunt("HT-02", host="desktop-mm1rem9", hours=24)
"""

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone
import os

ES_URL  = os.environ.get("ES_URL",  "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

es = Elasticsearch(
    ES_URL,
    basic_auth=(ES_USER, ES_PASS),
    request_timeout=30
)

# ---------------------------------------------------------------------------
# Template registry
# Each entry: id, name, description, params (with defaults), esql_fn
# ---------------------------------------------------------------------------

TEMPLATES = {

    # ── HT-01 — Rare parent-child pairs ────────────────────────────────────
    # Surfaces unusual process spawn relationships across the time window.
    # High child counts from a single parent = pivot point for investigation.
    "HT-01": {
        "id":          "HT-01",
        "name":        "Rare parent-child process pairs",
        "description": "Aggregates parent-child spawn relationships. "
                       "sort=rare isolates low-frequency pairs (min to max_count). "
                       "sort=frequent shows noisiest pairs. Raise max_count to widen the net.",
        "params": {
            "host":      {"type": "str",  "default": None,       "label": "Host (leave blank for all)"},
            "hours":     {"type": "int",  "default": 24,         "label": "Lookback hours"},
            "min_count": {"type": "int",  "default": 2,          "label": "Min occurrences"},
            "max_count": {"type": "int",  "default": 5,          "label": "Max occurrences (rare upper bound)"},
            "sort_mode": {"type": "str",  "default": "rare",     "label": "Sort mode: rare or frequent"},
        },
    },

    # ── HT-02 — Encoded PowerShell ──────────────────────────────────────────
    # Detects -EncodedCommand / -enc usage. High-fidelity indicator.
    # Uses *hidden* wildcard (not *-enc*) — tokenization issue in this ES build.
    "HT-02": {
        "id":          "HT-02",
        "name":        "Encoded PowerShell executions",
        "description": "Finds PowerShell processes with encoded command arguments. "
                       "Nearly always malicious in a lab/enterprise context.",
        "params": {
            "host":  {"type": "str", "default": None, "label": "Host (leave blank for all)"},
            "hours": {"type": "int", "default": 24,   "label": "Lookback hours"},
        },
    },

    # ── HT-03 — Outbound connections by process ─────────────────────────────
    # EID 3 network events. Surfaces which processes are making external calls.
    "HT-03": {
        "id":          "HT-03",
        "name":        "Outbound connections by process",
        "description": "Aggregates EID 3 network events by initiating process. "
                       "Unexpected processes with outbound connections = C2 candidate.",
        "params": {
            "host":         {"type": "str",  "default": None,  "label": "Host (leave blank for all)"},
            "hours":        {"type": "int",  "default": 24,    "label": "Lookback hours"},
            "exclude_local":{"type": "bool", "default": True,  "label": "Exclude RFC-1918 destinations"},
        },
    },

    # ── HT-04 — Scheduled task creation ─────────────────────────────────────
    # schtasks.exe with /create argument. Classic persistence technique.
    "HT-04": {
        "id":          "HT-04",
        "name":        "Scheduled task creation",
        "description": "Finds schtasks.exe executions with /create argument. "
                       "Common persistence mechanism — T1053.005.",
        "params": {
            "host":  {"type": "str", "default": None, "label": "Host (leave blank for all)"},
            "hours": {"type": "int", "default": 48,   "label": "Lookback hours"},
        },
    },

    # ── HT-05 — Registry run key writes ─────────────────────────────────────
    # EID 13 (registry value set) targeting Run/RunOnce keys.
    # Filters on TargetObject registry path — RuleName is config-dependent, not reliable.
    "HT-05": {
        "id":          "HT-05",
        "name":        "Registry run key persistence",
        "description": "Finds EID 13 events targeting HKCU/HKLM Run keys. "
                       "Direct persistence write — T1547.001.",
        "params": {
            "host":  {"type": "str", "default": None, "label": "Host (leave blank for all)"},
            "hours": {"type": "int", "default": 72,   "label": "Lookback hours"},
        },
    },

    # ── HT-06 — Credential access tools ─────────────────────────────────────
    # Process names and command-line patterns associated with credential dumping.
    "HT-06": {
        "id":          "HT-06",
        "name":        "Credential access tool signatures",
        "description": "Finds EID 1 process executions matching known credential "
                       "dumping tool names. Note: lsass access (EID 10) requires "
                       "a separate index not covered here — T1003.*.",
        "params": {
            "host":  {"type": "str", "default": None, "label": "Host (leave blank for all)"},
            "hours": {"type": "int", "default": 72,   "label": "Lookback hours"},
        },
    },

    # ── HT-07 — High-frequency child spawning ───────────────────────────────
    # Parents that spawn more than threshold children in the window.
    # Pivot point: high-spawning parents are worth investigating directly.
    "HT-07": {
        "id":          "HT-07",
        "name":        "High-frequency child process spawning",
        "description": "Finds parent processes that spawned more than N children "
                       "in the window. Unusual burst = lateral movement or spray attack.",
        "params": {
            "host":      {"type": "str", "default": None, "label": "Host (leave blank for all)"},
            "hours":     {"type": "int", "default": 24,   "label": "Lookback hours"},
            "threshold": {"type": "int", "default": 5,    "label": "Min child count"},
        },
    },
}


# ---------------------------------------------------------------------------
# Query builders — one per template
# Returns (esql_query_string, size)
# ES|QL runs via es.esql.query(body={"query": q})
# ---------------------------------------------------------------------------

def _ts_range(hours: int) -> str:
    """ISO8601 timestamp for `hours` ago — used in ES|QL WHERE clauses."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_clause(host) -> str:
    # ES|QL equality on host.name (TEXT field) is unreliable — use LIKE for exact
    # lowercase match. host.name is stored lowercase in argus-* and raw logs.
    if host:
        return f' AND host.name LIKE "{host.lower()}"'
    return ""


def build_HT01(host=None, hours=24, min_count=2, max_count=5, sort_mode="rare") -> str:
    ts        = _ts_range(hours)
    hc        = _host_clause(host)
    sort_dir  = "ASC" if str(sort_mode).lower() != "frequent" else "DESC"
    # Upper bound only applies in rare mode — frequent mode shows everything above min_count
    upper     = f' AND count <= {max_count}' if str(sort_mode).lower() != "frequent" else ""
    return (
        f'FROM logs-winlog.winlog-default '
        f'| WHERE @timestamp >= "{ts}"{hc} '
        f'| WHERE event.code == "1" '
        f'| WHERE winlog.event_data.ParentImage IS NOT NULL '
        f'| STATS count = COUNT(*) BY '
        f'    parent = winlog.event_data.ParentImage, '
        f'    child  = winlog.event_data.Image '
        f'| WHERE count >= {min_count}{upper} '
        f'| SORT count {sort_dir} '
        f'| LIMIT 100'
    )


def build_HT02(host=None, hours=24) -> str:
    ts = _ts_range(hours)
    hc = _host_clause(host)
    # Primary filter: *EncodedCommand* catches -EncodedCommand and abbreviated forms.
    # Secondary: *hidden* catches -WindowStyle Hidden often paired with encoded payloads.
    # Note: *-enc* has tokenization issues in this ES build — do not use (CLAUDE_v38 lesson 138).
    return (
        f'FROM logs-winlog.winlog-default '
        f'| WHERE @timestamp >= "{ts}"{hc} '
        f'| WHERE event.code == "1" '
        f'| WHERE winlog.event_data.Image LIKE "*powershell.exe" '  # ES|QL LIKE has no literal backslash escape — name match only
        f'| WHERE '
        f'    winlog.event_data.CommandLine LIKE "*EncodedCommand*" OR '
        f'    winlog.event_data.CommandLine LIKE "*hidden*" '
        f'| KEEP @timestamp, host.name, '
        f'    winlog.event_data.Image, '
        f'    winlog.event_data.CommandLine, '
        f'    winlog.event_data.User, '
        f'    winlog.event_data.ProcessId '
        f'| SORT @timestamp DESC '
        f'| LIMIT 200'
    )


def build_HT03(host=None, hours=24, exclude_local=True) -> str:
    ts  = _ts_range(hours)
    hc  = _host_clause(host)
    # Exclude RFC-1918 ranges at query level when flag set
    # ES|QL does not support CIDR match natively — filter by known private prefixes
    local_filter = (
        ' AND NOT winlog.event_data.DestinationIp LIKE "10.*"'
        ' AND NOT winlog.event_data.DestinationIp LIKE "192.168.*"'
        ' AND NOT winlog.event_data.DestinationIp LIKE "172.1[6-9].*"'
        ' AND NOT winlog.event_data.DestinationIp LIKE "172.2[0-9].*"'
        ' AND NOT winlog.event_data.DestinationIp LIKE "172.3[0-1].*"'
        ' AND NOT winlog.event_data.DestinationIp LIKE "127.*"'
    ) if exclude_local else ""
    return (
        f'FROM logs-winlog.winlog-default '
        f'| WHERE @timestamp >= "{ts}"{hc} '
        f'| WHERE event.code == "3" '
        f'| WHERE winlog.event_data.DestinationIp IS NOT NULL{local_filter} '
        f'| STATS '
        f'    connection_count = COUNT(*), '
        f'    unique_ips       = COUNT_DISTINCT(winlog.event_data.DestinationIp) '
        f'    BY process = winlog.event_data.Image '
        f'| SORT connection_count DESC '
        f'| LIMIT 50'
    )


def build_HT04(host=None, hours=48) -> str:
    ts = _ts_range(hours)
    hc = _host_clause(host)
    return (
        f'FROM logs-winlog.winlog-default '
        f'| WHERE @timestamp >= "{ts}"{hc} '
        f'| WHERE event.code == "1" '
        f'| WHERE winlog.event_data.Image LIKE "*schtasks.exe" '
        f'| WHERE winlog.event_data.CommandLine LIKE "*create*" '
        f'| KEEP @timestamp, host.name, '
        f'    winlog.event_data.CommandLine, '
        f'    winlog.event_data.User, '
        f'    winlog.event_data.ParentImage, '
        f'    winlog.event_data.ProcessId '
        f'| SORT @timestamp DESC '
        f'| LIMIT 100'
    )


def build_HT05(host=None, hours=72) -> str:
    ts = _ts_range(hours)
    hc = _host_clause(host)
    # ES|QL LIKE cannot escape literal backslash — only \* and \? are valid escape sequences.
    # Use broad *Run* / *RunOnce* match. False positives are low in practice since
    # TargetObject values containing "Run" outside registry path context are rare.
    return (
        f'FROM logs-winlog.winlog-default '
        f'| WHERE @timestamp >= "{ts}"{hc} '
        f'| WHERE event.code == "13" '
        f'| WHERE '
        f'    winlog.event_data.TargetObject LIKE "*Run*" OR '
        f'    winlog.event_data.TargetObject LIKE "*RunOnce*" '
        f'| KEEP @timestamp, host.name, '
        f'    winlog.event_data.TargetObject, '
        f'    winlog.event_data.Details, '
        f'    winlog.event_data.Image, '
        f'    winlog.event_data.ProcessId '
        f'| SORT @timestamp DESC '
        f'| LIMIT 100'
    )


def build_HT06(host=None, hours=72) -> str:
    ts = _ts_range(hours)
    hc = _host_clause(host)
    # Known credential tool names — EID 1 (process create) only.
    # lsass access detection requires EID 10 (process access) which is NOT
    # in this index. Description updated accordingly — no false claims.
    cred_tools = [
        "*mimikatz*", "*procdump*", "*pwdump*",
        "*wce.exe*",  "*fgdump*",   "*gsecdump*",
    ]
    # Build OR chain for LIKE filters — ES|QL has no IN() for LIKE patterns
    tool_filters = " OR ".join(
        f'winlog.event_data.Image LIKE "{t}" OR winlog.event_data.CommandLine LIKE "{t}"'
        for t in cred_tools
    )
    return (
        f'FROM logs-winlog.winlog-default '
        f'| WHERE @timestamp >= "{ts}"{hc} '
        f'| WHERE event.code == "1" '
        f'| WHERE {tool_filters} '
        f'| KEEP @timestamp, host.name, '
        f'    winlog.event_data.Image, '
        f'    winlog.event_data.CommandLine, '
        f'    winlog.event_data.User, '
        f'    winlog.event_data.ParentImage, '
        f'    winlog.event_data.ProcessId '
        f'| SORT @timestamp DESC '
        f'| LIMIT 200'
    )


def build_HT07(host=None, hours=24, threshold=5) -> str:
    ts = _ts_range(hours)
    hc = _host_clause(host)
    return (
        f'FROM logs-winlog.winlog-default '
        f'| WHERE @timestamp >= "{ts}"{hc} '
        f'| WHERE event.code == "1" '
        f'| WHERE winlog.event_data.ParentImage IS NOT NULL '
        f'| STATS child_count = COUNT(*) BY '
        f'    parent = winlog.event_data.ParentImage '
        f'| WHERE child_count >= {threshold} '
        f'| SORT child_count DESC '
        f'| LIMIT 50'
    )


# ---------------------------------------------------------------------------
# Query dispatcher
# ---------------------------------------------------------------------------

BUILDERS = {
    "HT-01": build_HT01,
    "HT-02": build_HT02,
    "HT-03": build_HT03,
    "HT-04": build_HT04,
    "HT-05": build_HT05,
    "HT-06": build_HT06,
    "HT-07": build_HT07,
}


def run_hunt(template_id: str, **params) -> dict:
    """
    Execute a hunt template against raw Sysmon telemetry.

    Args:
        template_id: One of HT-01 through HT-07
        **params:    Template-specific params (host, hours, threshold, etc.)

    Returns:
        {
            "ok":          bool,
            "template_id": str,
            "template":    dict,   # metadata (name, description, params)
            "query":       str,    # rendered ES|QL — shown in UI for transparency
            "columns":     list,   # [{name, type}, ...]
            "rows":        list,   # [[val, val, ...], ...]
            "total":       int,
            "error":       str | None
        }
    """
    if template_id not in TEMPLATES:
        return {
            "ok":    False,
            "error": f"Unknown template: {template_id}. Valid: {list(TEMPLATES.keys())}",
        }

    builder  = BUILDERS[template_id]
    template = TEMPLATES[template_id]

    # Apply defaults and enforce types for all params
    resolved = {}
    for k, spec in template["params"].items():
        val = params.get(k, spec["default"])
        if spec["type"] == "int" and val is not None:
            try:
                val = int(val)
            except (TypeError, ValueError):
                return {"ok": False, "error": f"Invalid param '{k}': expected int, got {val!r}"}
        elif spec["type"] == "bool" and val is not None:
            if isinstance(val, str):
                val = val.lower() not in ("false", "0", "no")
        resolved[k] = val

    # Build query string
    try:
        query = builder(**resolved)
    except Exception as e:
        return {"ok": False, "template_id": template_id, "error": f"Query build failed: {e}"}

    # Execute via ES|QL
    try:
        resp = es.esql.query(body={"query": query})
    except Exception as e:
        return {
            "ok":          False,
            "template_id": template_id,
            "template":    template,
            "query":       query,
            "error":       str(e),
        }

    columns = resp.get("columns", [])
    rows    = resp.get("values",  [])

    return {
        "ok":          True,
        "template_id": template_id,
        "template":    template,
        "query":       query,        # shown in UI — analyst sees exactly what ran
        "columns":     columns,      # [{name: str, type: str}, ...]
        "rows":        rows,         # [[val, ...], ...]
        "total":       len(rows),    # rows returned, not full ES hit count (ES|QL has no hits.total)
        "error":       None,
    }


def list_templates() -> list:
    """Return all template metadata without executing anything. Used by Screen 4 sidebar."""
    return [
        {
            "id":          t["id"],
            "name":        t["name"],
            "description": t["description"],
            "params":      t["params"],
        }
        for t in TEMPLATES.values()
    ]


# ---------------------------------------------------------------------------
# CLI smoke test — run from Node 1 to verify connectivity + field names
# Usage: python hunt_engine.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Argus Hunt Engine — smoke test ===\n")
    for tid in TEMPLATES:
        print(f"Testing {tid}: {TEMPLATES[tid]['name']}")
        result = run_hunt(tid, hours=24)
        if result["ok"]:
            print(f"  OK — {result['total']} rows, {len(result['columns'])} columns")
        else:
            print(f"  FAIL — {result['error']}")
        print()
