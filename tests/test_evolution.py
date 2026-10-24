from pathlib import Path

import pytest

from lab.attackers.evolution import evolve, policy_targets
from lab.corpus import load
from packages.policy import compile_policy


def test_evolution_uses_feedback_is_seeded_and_respects_budget():
    attack = load()[0]
    result, trace = evolve("rag", attack, "detector", seed=42, budget=64)
    assert attack.oracle.succeeds(result)
    assert len(trace) <= 64
    assert trace == evolve("rag", attack, "detector", seed=42, budget=64)[1]
    result, trace = evolve("rag", attack, "full-ifc", budget=8)
    assert not attack.oracle.succeeds(result) and len(trace) == 8
    with pytest.raises(ValueError):
        evolve("rag", attack, "full-ifc", budget=0)


def test_policy_aware_targets_include_actual_argument_and_approval_rules():
    targets = policy_targets(compile_policy(Path("packages/policy/default.yaml").read_text()))
    assert {
        "tool": "send_email",
        "argument": "recipient",
        "attack": "untrusted-destination",
    } in targets
    assert {"tool": "send_email", "argument": "*", "attack": "approval-bypass"} in targets
