import json

import pytest

from agents.cases import resolve_case
from agents.email import run_email
from agents.outcomes import expected_facts
from agents.scenarios import SUITE_SCENARIOS, integrity_targets
from agents.workflows import Records
from tests.test_email_agent import POLICY
from tests.test_record_workflows import Script

PLAN = {"instructions": [{"op": "call", "tool": "summarize", "arguments": {"text": "document"}}]}


@pytest.mark.anyio
@pytest.mark.parametrize("base", SUITE_SCENARIOS)
async def test_recovery_returns_checked_source_answer_not_unusable_model_text(base):
    case = resolve_case(base)
    result = await run_email(
        Script([{"bad": "plan"}, {"bad": "answer"}]),
        "script",
        POLICY,
        case.email,
        scenario_override=case,
    )
    assert result.status == "completed" and result.utility_success and not result.attack_success
    assert result.model_calls == 2 and result.model_protocol_errors == 2
    assert result.model_recoveries == ("planner-schema", "extraction-schema")
    assert all(str(v) in result.answer for v in expected_facts(case).values())
    assert "bad" not in result.answer and not result.effects


@pytest.mark.anyio
async def test_recovery_does_not_hide_provider_failure_or_unauthorized_valid_program():
    case = resolve_case("finance-workflow")

    class Failing:
        async def complete(self, messages, model):
            raise RuntimeError("provider unavailable")

    result = await run_email(Failing(), "script", POLICY, case.email, scenario_override=case)
    assert result.status == "error" and not result.model_recoveries and not result.answer
    bad = {"instructions": [{"op": "call", "tool": "shell", "arguments": {"text": "document"}}]}
    result = await run_email(
        Script([bad, expected_facts(case)]), "script", POLICY, case.email, scenario_override=case
    )
    assert result.status == "blocked" and not result.effects and not result.model_recoveries
    result = await run_email(
        Script([{"bad": "plan"}]),
        "script",
        POLICY,
        case.email,
        scenario_override=case,
        grounding="off",
    )
    assert result.status == "error" and not result.answer
    result = await run_email(
        Script([{"bad": "plan"}]),
        "script",
        POLICY,
        case.email,
        scenario_override=case,
        recover_model_errors=False,
    )
    assert result.status == "error" and not result.model_recoveries


@pytest.mark.anyio
@pytest.mark.parametrize("base", ("support-workflow", "access-workflow"))
async def test_legitimate_billing_and_approved_answers_are_not_attack_success(base):
    case = resolve_case(base, "development", 1)
    facts = expected_facts(case)
    tools = Records(case.kind, facts, source_records=case.records).trusted_reads()
    result = await run_email(
        Script(
            [
                *[{"action": tool, **args} for tool, args in tools],
                {"action": "finish", "facts": facts},
            ]
        ),
        "script",
        POLICY,
        case.email,
        "none",
        scenario_override=case,
        attack_goal="integrity",
    )
    assert result.utility_success and not result.attack_success
    targets = integrity_targets(case)
    assert all(facts[k] != v for k, v in targets.items())


def test_case_bank_contains_different_real_decisions_and_source_records_are_independent():
    support = [resolve_case("support-workflow", "development", i) for i in range(5)]
    access = [resolve_case("access-workflow", "development", i) for i in range(5)]
    assert {c.expected[1] for c in support} == {"normal", "high"}
    assert {c.expected[2] for c in support} == {"identity", "billing"}
    assert len({c.expected[3] for c in support}) == 3
    assert {c.expected[2] for c in access} == {"approved", "needs-approval"}
    case = support[1]
    records = Records(case.kind, expected_facts(case), source_records=case.records)
    records.data["lookup_ticket"]["issue_code"] = "login-failure"
    assert case.records["lookup_ticket"]["issue_code"] == "billing-error"
    assert (
        json.loads(records.read("lookup_ticket", {"ticket_id": case.expected[0]}))["record"][
            "issue_code"
        ]
        == "login-failure"
    )
