"""
dispatcher.py - loads a scenario fixture, runs it through every registered
workflow, and applies the one central decision rule.

Concrete workflow classes live in this file rather than a separate
`workflows.py`. That's a deliberate choice, not an oversight: their only
consumer is the decision rule at the bottom of this file, and keeping them
next to the rule that counts their hits means the entire NOISE/SIGNAL
decision - what gets checked, and how the checks get combined - is
readable in one place instead of split across the package. workflow_base.py
still holds the shared interface, since that's the part other code
(and future workflows) depends on.
"""

import json
from pathlib import Path
from typing import List

from hermes.state_manager import StateManager
from hermes.workflow_base import WorkflowBase

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Concrete workflows
# ---------------------------------------------------------------------------

class EncodedCommandWorkflow(WorkflowBase):
    name = "encoded_command"

    def evaluate(self, evidence: List[dict], state: StateManager) -> bool:
        for item in evidence:
            if item.get("type") == "process_create" and item.get("encoded"):
                state.add_reason(
                    f"Encoded PowerShell execution: {item.get('image', 'unknown image')}",
                    [item["evidence_id"]],
                )
                return True
        return False


class PersistenceWorkflow(WorkflowBase):
    name = "persistence"

    def evaluate(self, evidence: List[dict], state: StateManager) -> bool:
        for item in evidence:
            if item.get("type") == "registry_write" and "\\Run\\" in item.get("target_object", ""):
                state.add_reason(
                    f"Registry Run key persistence written: {item['target_object']}",
                    [item["evidence_id"]],
                )
                return True
            if item.get("type") == "scheduled_task_create":
                state.add_reason(
                    f"Scheduled task persistence created: {item.get('task_name', 'unknown task')}",
                    [item["evidence_id"]],
                )
                return True
        return False


class NetworkCorroborationWorkflow(WorkflowBase):
    """
    Looks for two independent evidence items, one EDR-side network
    connection and one NDR-side flow record, agreeing on the same
    destination IP and port. This is the same dual-source pattern used
    elsewhere in this repo (see IR-006's cross-layer corroboration): a
    single sensor's claim is weaker evidence than two independently
    collected sensors agreeing on the same connection.
    """
    name = "network_corroboration"

    def evaluate(self, evidence: List[dict], state: StateManager) -> bool:
        edr_conns = [
            e for e in evidence
            if e.get("type") == "network_connection" and e.get("source") == "edr"
        ]
        ndr_flows = [
            e for e in evidence
            if e.get("type") == "http_flow" and e.get("source") == "ndr"
        ]

        for edr in edr_conns:
            for ndr in ndr_flows:
                if (
                    edr.get("destination_ip") == ndr.get("destination_ip")
                    and edr.get("destination_port") == ndr.get("destination_port")
                ):
                    state.add_reason(
                        f"Independent EDR+NDR corroboration on "
                        f"{edr['destination_ip']}:{edr['destination_port']}",
                        [edr["evidence_id"], ndr["evidence_id"]],
                    )
                    return True
        return False


class BenignSingleProcessWorkflow(WorkflowBase):
    """
    The NOISE-side explanation. Fires when the evidence set is a single
    process execution and none of the signal workflows matched anything
    in it. This exists so a NOISE verdict still comes with a cited reason
    instead of just "nothing else fired" - silence isn't an acceptable
    output shape here. Every verdict, NOISE or SIGNAL, must point at
    specific evidence.
    """
    name = "benign_single_process"

    def evaluate(self, evidence: List[dict], state: StateManager) -> bool:
        if len(evidence) == 1 and evidence[0].get("type") == "process_create":
            item = evidence[0]
            state.add_reason(
                "Single process execution with no persistence, encoding, "
                f"or network corroboration: {item.get('image', 'unknown image')}",
                [item["evidence_id"]],
            )
            return True
        return False


# Order here only controls the order reasons appear in output. It has no
# effect on the decision itself - the rule below counts hits, it doesn't
# care which workflow fired first.
SIGNAL_WORKFLOWS = [
    EncodedCommandWorkflow(),
    PersistenceWorkflow(),
    NetworkCorroborationWorkflow(),
]
NOISE_WORKFLOWS = [
    BenignSingleProcessWorkflow(),
]


# ---------------------------------------------------------------------------
# Fixture loading and the decision rule
# ---------------------------------------------------------------------------

def load_fixture(scenario: str) -> dict:
    path = FIXTURES_DIR / f"{scenario}.json"
    if not path.exists():
        raise FileNotFoundError(f"No fixture for scenario {scenario!r} at {path}")
    with open(path) as f:
        return json.load(f)


def run_scenario(scenario: str) -> dict:
    """
    Runs one scenario end to end: load fixture, run every signal workflow
    against its evidence, then apply the decision rule.

    Decision rule - deterministic, plain conditional logic, no LLM call
    anywhere in this path: two or more independently-fired signal
    categories (encoded execution, persistence, network corroboration)
    means SIGNAL. A single suspicious-looking indicator on its own is
    common enough to be noise; two or more independent categories
    agreeing is what elevates it. This mirrors the same "multiple tactic
    categories" bar Argus's own case classification uses elsewhere in
    this repo, applied here as an explicit, auditable count instead of an
    opaque score.
    """
    fixture = load_fixture(scenario)
    evidence = fixture["evidence"]
    state = StateManager(evidence)

    signal_hits = sum(1 for wf in SIGNAL_WORKFLOWS if wf.evaluate(evidence, state))

    if signal_hits >= 2:
        decision = "SIGNAL"
    else:
        decision = "NOISE"
        for wf in NOISE_WORKFLOWS:
            wf.evaluate(evidence, state)

    return {
        "decision": decision,
        "signal_hits": signal_hits,
        "state": state,
        "case_id": fixture.get("case_id"),
    }
