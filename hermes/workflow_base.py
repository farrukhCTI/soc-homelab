"""
workflow_base.py - the interface every Hermes workflow implements.

A workflow inspects the evidence list for one specific pattern (encoded
execution, persistence, network corroboration, etc.) and, if it finds a
match, calls state.add_reason() with a plain-language explanation and the
exact evidence_ids that back it.

A workflow never assigns NOISE or SIGNAL. That decision is made exactly
once, centrally, in dispatcher.py, by counting how many independent
workflows fired. Keeping workflows single-purpose and decision-free is
what keeps the overall verdict auditable: each workflow is a small,
independently-testable predicate over the evidence list, not a black box
that gets to make the final call on its own.
"""

from abc import ABC, abstractmethod
from typing import List

from hermes.state_manager import StateManager


class WorkflowBase(ABC):
    name: str = "unnamed_workflow"

    @abstractmethod
    def evaluate(self, evidence: List[dict], state: StateManager) -> bool:
        """
        Inspect `evidence` for this workflow's pattern.

        If the pattern is found: call state.add_reason(...) and return True.
        If not found: return False without touching state.

        Must never raise on missing or malformed fields - evidence is
        fixture data being inspected, not application state the workflow
        controls, so a missing key means "pattern not present here," not
        a crash.
        """
        raise NotImplementedError
