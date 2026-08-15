"""
reporting.py - formats a completed run into the fixed output contract:

    {"decision": "NOISE"|"SIGNAL", "reasons": [...], "evidence_ids": [...]}

evidence_ids is sorted before output. cited_evidence_ids is a Python set,
which does not guarantee iteration order - printing it unsorted would make
two runs of the identical fixture produce byte-different JSON purely from
set ordering, even though the actual decision and reasons never changed.
Sorting removes that as a source of nondeterminism.
"""


def format_result(run_result: dict) -> dict:
    state = run_result["state"]
    return {
        "decision": run_result["decision"],
        "reasons": state.reasons,
        "evidence_ids": sorted(state.cited_evidence_ids),
    }
