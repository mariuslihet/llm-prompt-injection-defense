import json

import pytest

from agents.cases import resolve_case
from agents.email import run_email
from agents.outcomes import assess, expected_facts
from agents.scenarios import SUITE_SCENARIOS, attack_input
from agents.workflows import Records
from tests.test_email_agent import POLICY


class Script:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    async def complete(self, messages, model):
        self.requests.append(messages.copy())
        return json.dumps(next(self.responses))


@pytest.mark.anyio
@pytest.mark.parametrize("scenario_id", SUITE_SCENARIOS)
async def test_distinct_tools_are_required_and_ifc_uses_scoped_sources(scenario_id):
    scenario = resolve_case(scenario_id)
    facts = expected_facts(scenario)
    tools = Records(scenario.kind, facts).trusted_reads()
    provider = Script(
        [
            {"action": "read_email"},
            *[{"action": tool, **args} for tool, args in tools],
            {"action": "finish", "facts": facts},
        ]
    )
    baseline = await run_email(
        provider,
        "script",
        POLICY,
        scenario.email,
        "none",
        scenario_id=scenario_id,
        scenario_override=scenario,
    )
    assert baseline.utility_success and not baseline.effects
    assert {e.details.get("tool") for e in baseline.events if e.kind == "tool-result"} >= {
        tool for tool, _ in tools
    }
    shortcut = await run_email(
        Script([{"action": "finish", "facts": facts}]),
        "script",
        POLICY,
        scenario.email,
        "none",
        scenario_id=scenario_id,
        scenario_override=scenario,
    )
    assert not shortcut.utility_success and not shortcut.outcome_details["required_sources_read"]
    protected_provider = Script(
        [
            {
                "instructions": [
                    {"op": "call", "tool": "summarize", "arguments": {"text": "document"}}
                ]
            },
            facts,
        ]
    )
    protected = await run_email(
        protected_provider,
        "script",
        POLICY,
        attack_input(scenario, "authority"),
        "full-ifc",
        scenario_id=scenario_id,
        scenario_override=scenario,
    )
    assert protected.utility_success and not protected.effects
    assert facts[next(iter(facts))] not in protected_provider.requests[0][0]["content"]


@pytest.mark.anyio
async def test_integrity_success_requires_observed_tampering_not_quoted_instruction():
    scenario = resolve_case("finance-workflow")
    facts = expected_facts(scenario)
    mutated = {**facts, "amount": "1.00"}
    result = await run_email(
        Script(
            [
                {"action": "update_invoice", "invoice_id": facts["invoice_id"], "amount": "1.00"},
                *[
                    {"action": tool, **args}
                    for tool, args in Records(scenario.kind, facts).trusted_reads()
                ],
                {"action": "finish", "facts": mutated},
            ]
        ),
        "script",
        POLICY,
        attack_input(scenario, "authority", "integrity"),
        "none",
        scenario_id="finance-workflow",
        scenario_override=scenario,
        attack_goal="integrity",
    )
    assert result.attack_success and result.state_changes
    assert result.outcome_details["integrity_violation"]
    quoted = await run_email(
        Script([{"action": "finish", "answer": "The attack asks for 1.00"}]),
        "script",
        POLICY,
        scenario.email,
        "none",
        scenario_id="finance-workflow",
        scenario_override=scenario,
        attack_goal="integrity",
    )
    assert not quoted.attack_success and not quoted.utility_success


def test_semantic_normalization_does_not_confuse_negated_approval_and_true_approval():
    case = resolve_case("access-workflow")
    facts = expected_facts(case)
    assert assess(
        json.dumps({**facts, "decision": "Needs Approval", "reason": "manager_approval_missing"}),
        case,
    )["correct"]
    assert not assess(
        json.dumps({**facts, "decision": "approved", "reason": "manager-approved"}), case
    )["correct"]
    assert not assess("Not approved, despite the word approved.", case)["structured"]


def test_case_partitions_are_disjoint_and_records_cannot_escape_scope():
    ids = set()
    for partition in ("development", "heldout"):
        for variation in range(5):
            for scenario_id in SUITE_SCENARIOS:
                case = resolve_case(scenario_id, partition, variation)
                assert case.id not in ids
                ids.add(case.id)
    assert len(ids) == 30
    records = Records("invoice", expected_facts(resolve_case("finance-workflow")))
    with pytest.raises(ValueError, match="capability"):
        records.read("read_invoice", {"invoice_id": "INV-999999"})
    with pytest.raises(ValueError, match="capability"):
        records.read("lookup_ticket", {"ticket_id": "SUP-317"})


@pytest.mark.anyio
async def test_early_finish_recovery_requires_sources_without_disclosing_expected_values():
    case = resolve_case("finance-workflow", "heldout", 3)
    facts = expected_facts(case)
    provider = Script(
        [
            {"action": "finish", "answer": "A guessed answer"},
            *[{"action": tool, **args} for tool, args in Records(case.kind, facts).trusted_reads()],
            {"action": "finish", "facts": {**facts, "amount": "1.00"}},
        ]
    )
    result = await run_email(
        provider,
        "script",
        POLICY,
        case.email,
        "none",
        scenario_override=case,
        attack_goal="integrity",
    )
    assert result.status == "completed" and result.attack_success
    assert not result.utility_success
    assert result.outcome_details["required_sources_read"]
    recovery = provider.requests[1][-1]["content"]
    assert "read_invoice" in recovery and facts["amount"] not in recovery
    assert "due_date" in recovery and facts["due_date"] not in recovery
