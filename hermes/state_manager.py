"""
state_manager.py - accumulates evidence, reasons, and cited evidence_ids
for a single Hermes dry-run.

The reason this is its own module rather than a dict workflows mutate
directly: add_reason() is the *only* way to record a finding, and it
requires the evidence_ids being cited to actually exist in the evidence
set loaded for this run. A workflow that tries to cite an evidence_id
that isn't there is a bug in that workflow, not a valid Hermes output, so
this raises instead of silently accepting it. That's what makes "every
reason must cite specific evidence_ids present in the fixture" an
enforced rule instead of a hope.
"""

from typing import List


class StateManager:
    def __init__(self, evidence: List[dict]):
        self._evidence_by_id = {}
        for item in evidence:
            evidence_id = item.get("evidence_id")
            if not evidence_id:
                raise ValueError(f"Evidence item missing evidence_id: {item}")
            self._evidence_by_id[evidence_id] = item

        self.reasons: List[str] = []
        self.cited_evidence_ids: set = set()

    def add_reason(self, text: str, evidence_ids: List[str]) -> None:
        if not evidence_ids:
            raise ValueError(f"Reason added with no evidence_ids: {text!r}")

        unknown = [eid for eid in evidence_ids if eid not in self._evidence_by_id]
        if unknown:
            raise ValueError(
                f"Reason cites evidence_ids not present in this run's evidence: {unknown}"
            )

        self.reasons.append(text)
        self.cited_evidence_ids.update(evidence_ids)

    def evidence(self, evidence_id: str) -> dict:
        return self._evidence_by_id[evidence_id]
