from copy import deepcopy

import pytest

from lab.campaigns import RunSpec, execute
from lab.comparison import compare
from tests.test_email_agent import POLICY, ScriptedProvider


def job():
    return {
        "id": "current",
        "status": "completed",
        "result": {
            "dataset_digest": "same-inputs",
            "model": "local",
            "policy_digest": "policy",
            "summary": [
                {
                    "defense": "full-ifc",
                    "attack_successes": 0,
                    "benign_successes": 3,
                    "p95_ms": 10,
                    "conclusive": True,
                }
            ],
        },
    }


def test_comparison_rejects_mismatches_and_marks_invalid_results_inconclusive():
    current, previous = job(), job()
    previous["id"] = "baseline"
    assert compare(current, previous)["rows"][0]["status"] == "unchanged"
    current["result"]["summary"][0]["attack_successes"] = 1
    assert compare(current, previous)["rows"][0]["status"] == "regression"
    current["result"]["summary"][0]["conclusive"] = False
    assert compare(current, previous)["rows"][0]["status"] == "inconclusive"
    different = deepcopy(previous)
    different["result"]["dataset_digest"] = "different-inputs"
    with pytest.raises(ValueError, match="different"):
        compare(current, different)
    previous["status"] = "running"
    with pytest.raises(ValueError, match="completed"):
        compare(current, previous)


@pytest.mark.anyio
async def test_suite_executes_all_scenarios_with_shared_bounded_calls_and_snapshot():
    progress = []

    async def update(value):
        progress.append(value)

    result = await execute(
        RunSpec(kind="suite", adaptive_rounds=0),
        ScriptedProvider(),
        "script",
        POLICY,
        "tenant",
        update,
    )
    assert len(result["records"]) == 30
    assert len({(r["scenario_id"], r["case"], r["payload_sha256"]) for r in result["records"]}) == 6
    assert len({id(r["run"]["events"]) for r in result["records"]}) == 30
    assert all(r["task"] and r["scenario_id"] for r in result["records"])
    assert len(result["scenario_results"]) == 3
    assert result["model_calls"] <= 180
    assert len(result["dataset_digest"]) == 64
    assert {r["scenario_id"] for r in result["records"]} == {
        "finance-workflow",
        "support-workflow",
        "access-workflow",
    }
    assert progress[-1]["completed_runs"] == 30
    assert all(r["benign_trials"] == 3 and r["attack_trials"] == 3 for r in result["summary"])
    with pytest.raises(ValueError, match="static"):
        RunSpec(kind="suite", adaptive_rounds=2)


@pytest.mark.anyio
async def test_suite_cannot_reset_call_budget_between_scenarios():
    class InvalidProvider:
        calls = 0

        async def complete(self, messages, model):
            self.calls += 1
            return "invalid"

    async def update(value):
        pass

    provider = InvalidProvider()
    result = await execute(
        RunSpec(kind="suite", adaptive_rounds=0, max_turns=8),
        provider,
        "script",
        POLICY,
        "tenant",
        update,
    )
    # Per scenario: two 16-call agents, two 8-call agents (static attacks blocked),
    # and two invalid planner calls. Detector blocks consume no provider calls.
    assert provider.calls == result["model_calls"] == 150
    assert result["model_calls"] <= 240
    assert all(not row["conclusive"] for row in result["summary"])
