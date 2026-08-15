"""
seed_argus.py — loads the datasets/ snapshot into Elasticsearch.

Run inside the argus-api image with datasets/ mounted at /data:
    docker compose run --rm seed

WHY THIS ISN'T A DUMB BULK IMPORT:

1. Case metadata (behavior_count, risk_score, blast_radius, highest_severity,
   tactics_seen) is RECOMPUTED from the actual behaviors being loaded for
   that case, using case_builder.py's own scoring functions — not trusted
   from the stored case JSON. Comparing the two on disk:

       CASE-001: declared behavior_count=247, actual behaviors file has 2
       CASE-002: declared behavior_count=51,  actual behaviors file has 0
       CASE-003: declared behavior_count=54,  actual behaviors file has 0
       CASE-004/005/006: match.

   The stored counts are stale — the behaviors export was regenerated at
   some point after the case snapshot was taken, and the case doc was
   never refreshed. Loading the stale numbers as-is would put a case card
   in the UI claiming 51 behaviors that opens to an empty timeline — the
   exact claim-vs-artifact gap this whole remediation is about, just
   showing up in the seed data itself instead of the README.

2. argus-actions-2026-05-16.json has 10 records. None of them cleanly
   reference a real, currently-existing behavior:

     - 1 action targets case_id "CASE-011", which does not exist anywhere
       in argus-cases-2026-05-16.json (only CASE-001..006 exist).
     - 6 actions target CASE-002, which has zero real behaviors after
       recomputation (see above) — there is nothing valid to attach them to.
     - Both of the above also have behavior_id set equal to case_id, which
       looks like a UI/logging bug where a case-level action got the case's
       own ID written into the behavior_id field instead of a real
       behavior_id.
     - The remaining 3 actions reference BEH-J1EPLP0B and BEH-1C1YKJ0B —
       IDs that don't match the current behavior_detector.py ID format
       (BEH-<8char>-<profile>) and don't exist in any behaviors-*.json
       file. Likely explanation: these were recorded against an earlier
       generation of behaviors, before the underlying Sysmon index was
       re-ingested and behavior_detector regenerated IDs (which are
       derived from the raw event's ES _id — reindexing changes them).

   Decision: the 7 records with no honest target (CASE-011, and all 6
   CASE-002 ones) are dropped — there is no real behavior to attach them
   to and fabricating one would be worse than omitting it. The 3 records
   with real analyst content (two ESCALATEs and one genuine note, "Its
   normal. not problematic") are kept and remapped onto a real behavior_id
   from the case they were actually filed against, so the analyst-action
   demo isn't just empty. This is a logged, visible remap — not a silent
   patch — see REMAPPED_ACTIONS below and the printed output when this runs.
"""

import json
import os
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

from case_builder import compute_blast_radius, compute_grouped_by

DATA_DIR = os.environ.get("SEED_DATA_DIR", "/data")

ES_URL  = os.environ.get("ES_URL",  "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), request_timeout=30)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEVERITY_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Dropped outright: behavior_id == case_id (bugged case-level logging) or
# a case_id that doesn't exist in argus-cases-2026-05-16.json at all.
DROP_ACTION_TARGETS = {"CASE-011", "CASE-002"}

# Stale-but-real actions remapped onto a real current behavior_id from the
# same case, keyed by the stale behavior_id in the source file.
REMAPPED_ACTIONS = {
    "BEH-J1EPLP0B": {"case_id": "CASE-005"},
    "BEH-1C1YKJ0B": {"case_id": "CASE-001"},
}


def load(name):
    with open(os.path.join(DATA_DIR, name)) as f:
        return json.load(f)


def delete_index(name):
    if es.indices.exists(index=name):
        es.indices.delete(index=name)
        print(f"[seed] deleted existing index {name}")


def seed_behaviors():
    behavior_ids_by_case = {}  # case_id -> [behavior_id, ...] as loaded
    total = 0

    cases = load("argus-cases-2026-05-16.json")["cases"]
    for case in cases:
        case_id = case["case_id"]
        fname = f"behaviors-{case_id}-2026-05-16.json"
        behaviors = load(fname)["behaviors"]

        ids = []
        for beh in behaviors:
            beh = {**beh, "case_id": case_id}
            es.index(index="argus-behaviors", id=beh["behavior_id"], document=beh)
            ids.append(beh["behavior_id"])
            total += 1

        behavior_ids_by_case[case_id] = ids
        print(f"[seed] {case_id}: indexed {len(ids)} behaviors from {fname}")

    # Elasticsearch is near-real-time, not immediately consistent: writes
    # only become searchable on the index's refresh cycle (default ~1s),
    # not the instant es.index() returns. seed_cases() right after this
    # re-queries argus-behaviors by case_id to compute case metadata — without
    # forcing a refresh here, whether that query sees all 358 just-written
    # docs depends on incidental timing rather than being guaranteed. This
    # was caught by literally re-running the script and getting a different
    # behavior_count for CASE-006 (52 vs. 27) on identical input.
    es.indices.refresh(index="argus-behaviors")
    print(f"[seed] total behaviors indexed: {total} (index refreshed, now searchable)")
    return cases, behavior_ids_by_case


def seed_cases(cases, behavior_ids_by_case):
    for case in cases:
        case_id = case["case_id"]
        ids = behavior_ids_by_case.get(case_id, [])

        if not ids:
            print(f"[seed] SKIPPED {case_id}: zero real behaviors after recomputation, "
                  f"not creating a case that would open to an empty timeline")
            continue

        # Refetch the actual indexed behavior docs so blast_radius/grouped_by
        # are computed from what's really in ES, using case_builder.py's own
        # logic — same (doc_id, behavior_dict) tuple shape it expects.
        resp = es.search(
            index="argus-behaviors",
            body={"size": 1000, "query": {"term": {"case_id.keyword": case_id}}},
        )
        items = [(hit["_id"], hit["_source"]) for hit in resp["hits"]["hits"]]

        blast_radius = compute_blast_radius(items)
        grouped_by = compute_grouped_by(items)
        severities = [b.get("severity", "MEDIUM") for _, b in items]
        highest_severity = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))
        tactics_seen = sorted({b.get("tactic", "") for _, b in items if b.get("tactic")})
        base_score = sum(b.get("priority_score", 50.0) for _, b in items)
        risk_score = base_score * SEVERITY_WEIGHT.get(highest_severity, 1)

        doc = {
            "case_id": case_id,
            "status": case.get("status", "OPEN"),
            "created_at": case.get("created_at", datetime.now(timezone.utc).isoformat()),
            "behavior_count": len(items),
            "grouped_by": grouped_by,
            "blast_radius": blast_radius,
            "highest_severity": highest_severity,
            "tactics_seen": tactics_seen,
            "risk_score": risk_score,
            # case_summary is Claude-generated prose, not re-derivable from
            # behaviors — keep whatever was actually stored, if anything.
            "case_summary": case.get("case_summary") or "",
        }

        stale_count = case.get("behavior_count")
        if stale_count != len(items):
            print(f"[seed] {case_id}: recomputed behavior_count {len(items)} "
                  f"(stored file claimed {stale_count}), risk_score {risk_score:.0f}")
        else:
            print(f"[seed] {case_id}: behavior_count {len(items)} confirmed, risk_score {risk_score:.0f}")

        es.index(index="argus-cases", id=case_id, document=doc)


def seed_actions(behavior_ids_by_case):
    actions = load("argus-actions-2026-05-16.json")["actions"]
    kept, dropped, remapped = 0, 0, 0

    for a in actions:
        beh_id = a.get("behavior_id")
        case_id = a.get("case_id")

        if beh_id in DROP_ACTION_TARGETS or case_id in DROP_ACTION_TARGETS:
            print(f"[seed] dropped action ({a.get('action')} on behavior_id={beh_id}, "
                  f"case_id={case_id}) — no real behavior to attach it to")
            dropped += 1
            continue

        if beh_id in REMAPPED_ACTIONS:
            target_case = REMAPPED_ACTIONS[beh_id]["case_id"]
            real_ids = behavior_ids_by_case.get(target_case, [])
            if not real_ids:
                print(f"[seed] dropped action ({a.get('action')} on stale {beh_id}) — "
                      f"{target_case} has no real behaviors to remap onto")
                dropped += 1
                continue
            new_beh_id = real_ids[0]
            print(f"[seed] remapped action ({a.get('action')}) from stale {beh_id} "
                  f"-> real {new_beh_id} (case {target_case})")
            beh_id = new_beh_id
            case_id = target_case
            remapped += 1

        doc = {
            "behavior_id": beh_id,
            "case_id": case_id,
            "action": a.get("action"),
            "note": a.get("note"),
            "actor": a.get("actor", "analyst"),
            "timestamp": a.get("timestamp"),
        }
        es.index(index="argus-actions", document=doc)
        kept += 1

    print(f"[seed] actions: {kept} kept ({remapped} remapped), {dropped} dropped")


def main():
    print(f"[seed] connecting to {ES_URL}")
    for idx in ("argus-cases", "argus-behaviors", "argus-actions"):
        delete_index(idx)

    cases, behavior_ids_by_case = seed_behaviors()
    seed_cases(cases, behavior_ids_by_case)
    seed_actions(behavior_ids_by_case)

    es.indices.refresh(index="argus-cases,argus-behaviors,argus-actions")
    print("[seed] done")


if __name__ == "__main__":
    main()
