import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agents.cases import resolve_case
from agents.email import run_email
from agents.outcomes import expected_facts
from agents.scenarios import SUITE_SCENARIOS
from agents.workflows import Records
from packages.core import Confidentiality, Label, Trust, Value
from packages.ifc import untrusted_value
from packages.ifc.grounding import GroundingError, ground_answer
from tests.test_email_agent import POLICY
from tests.test_record_workflows import Script

PROGRAM = {"instructions": [{"op": "call", "tool": "summarize", "arguments": {"text": "document"}}]}


def source_case(base="finance-workflow", note=""):
    case = resolve_case(base)
    records = Records(case.kind, expected_facts(case), note, source_records=case.records)
    evidence = {
        tool: untrusted_value(records.read(tool, args), tool)
        for tool, args in records.trusted_reads()
    }
    return case, records, evidence


@given(st.text(max_size=3000), st.integers(min_value=0, max_value=99999999))
def test_notes_and_model_amount_cannot_override_authoritative_fields(note, amount):
    case, _, evidence = source_case(note=note)
    candidate = untrusted_value(json.dumps({**expected_facts(case), "amount": f"{amount}.00"}))
    result = ground_answer(candidate, evidence, "invoice")
    assert json.loads(result.value.data)["amount"] == expected_facts(case)["amount"]
    assert result.value.label.trust == Trust.UNTRUSTED
    assert not result.value.label.allowed_sinks


def test_uses_changed_sources_not_evaluation_answers_and_preserves_private_labels():
    case, _, evidence = source_case()
    packet = json.loads(evidence["read_invoice"].data)
    packet["record"]["amount"] = "999.99"
    evidence["read_invoice"] = Value(
        data=json.dumps(packet),
        label=Label(
            sources=frozenset({"private-invoice"}),
            trust=Trust.UNTRUSTED,
            confidentiality=Confidentiality.PRIVATE,
            allowed_sinks=frozenset({"send_email"}),
        ),
    )
    result = ground_answer(untrusted_value(json.dumps(expected_facts(case))), evidence, "invoice")
    assert json.loads(result.value.data)["amount"] == "999.99"
    assert result.corrected_fields == ("amount",)
    assert result.value.label.confidentiality == Confidentiality.PRIVATE
    assert not result.value.label.allowed_sinks


@pytest.mark.parametrize("base", SUITE_SCENARIOS)
def test_missing_and_mismatched_sources_fail_closed(base):
    case, _, evidence = source_case(base)
    candidate = untrusted_value(json.dumps(expected_facts(case)))
    tools = list(evidence)
    with pytest.raises(GroundingError):
        ground_answer(candidate, {tools[0]: evidence[tools[0]]}, case.kind)
    packet = json.loads(evidence[tools[1]].data)
    key = {"invoice": "vendor_id", "support": "ticket_id", "access": "request_id"}[case.kind]
    packet["record"][key] = "different"
    evidence[tools[1]] = untrusted_value(json.dumps(packet))
    with pytest.raises(GroundingError):
        ground_answer(candidate, evidence, case.kind)
    with pytest.raises(GroundingError, match="covers"):
        ground_answer(candidate, evidence, "meeting")


def test_business_rules_follow_structured_impact_and_approval():
    for base, tool, updates, field, value in (
        (
            "support-workflow",
            "read_ticket_history",
            {"affected_users": 1, "work_blocked": False},
            "severity",
            "normal",
        ),
        (
            "access-workflow",
            "check_manager_approval",
            {"manager_approved": "yes"},
            "decision",
            "approved",
        ),
    ):
        case, _, evidence = source_case(base)
        packet = json.loads(evidence[tool].data)
        packet["record"].update(updates)
        evidence[tool] = untrusted_value(json.dumps(packet))
        result = ground_answer(
            untrusted_value(json.dumps(expected_facts(case))), evidence, case.kind
        )
        assert json.loads(result.value.data)[field] == value


def test_all_versioned_tasks_have_groundable_sources_and_bad_records_are_rejected():
    for partition in ("development", "heldout"):
        for variation in range(5):
            for base in SUITE_SCENARIOS:
                case = resolve_case(base, partition, variation)
                records = Records(case.kind, expected_facts(case), source_records=case.records)
                evidence = {
                    tool: untrusted_value(records.read(tool, args))
                    for tool, args in records.trusted_reads()
                }
                result = ground_answer(
                    untrusted_value(json.dumps(expected_facts(case))), evidence, case.kind
                )
                assert not result.corrected_fields
    case, _, evidence = source_case()
    evidence["lookup_vendor"] = untrusted_value('{"status":"success","record":[]}')
    with pytest.raises(GroundingError):
        ground_answer(untrusted_value(json.dumps(expected_facts(case))), evidence, "invoice")


@pytest.mark.anyio
async def test_unknown_source_check_mode_is_rejected_before_provider_call():
    case, _, _ = source_case()
    with pytest.raises(ValueError):
        await run_email(
            Script([]), "script", POLICY, case.email, scenario_override=case, grounding="typo"
        )


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ("off", "shadow", "enforce"))
async def test_integrity_ablation_modes_preserve_proposal_and_utility(mode):
    case, _, _ = source_case()
    wrong = {**expected_facts(case), "amount": "1.00"}
    result = await run_email(
        Script([PROGRAM, wrong]),
        "script",
        POLICY,
        case.email,
        scenario_override=case,
        attack_goal="integrity",
        grounding=mode,
    )
    assert result.status == "completed"
    assert result.attack_success == (mode != "enforce")
    assert result.utility_success == (mode == "enforce")
    assert result.model_calls == 2
    if mode != "off":
        assert (
            json.loads(result.outcome_details["grounding"]["proposed_answer"])["amount"] == "1.00"
        )


@pytest.mark.anyio
async def test_bad_adapter_evidence_is_withheld_and_program_cannot_rewrite_answer(monkeypatch):
    case, _, _ = source_case()
    provider = Script(
        [
            {
                "instructions": [
                    {"op": "concat", "left": "document", "right": "document", "output": "changed"},
                    {"op": "call", "tool": "summarize", "arguments": {"text": "changed"}},
                ]
            },
            expected_facts(case),
        ]
    )
    result = await run_email(provider, "script", POLICY, case.email, scenario_override=case)
    assert result.status == "blocked" and not result.answer
    assert result.error_code == "source_validation_failed"
    original = Records.read

    def broken(self, tool, arguments):
        return '{"status":"error"}' if tool == "lookup_vendor" else original(self, tool, arguments)

    monkeypatch.setattr(Records, "read", broken)
    result = await run_email(
        Script([PROGRAM, expected_facts(case)]),
        "script",
        POLICY,
        case.email,
        scenario_override=case,
    )
    assert result.status == "blocked" and not result.answer
    assert not result.utility_success


def test_ablation_reports_new_adaptive_attempts_separately_from_seed_success():
    from eval.grounding_ablation import summarize

    run = {
        "attack_success": False,
        "utility_success": True,
        "status": "completed",
        "error_code": None,
        "outcome_details": {},
        "model_calls": 2,
        "duration_ms": 1.0,
    }
    summary = summarize(
        [
            {"case": "benign", "run": run},
            {"case": "static", "run": {**run, "attack_success": True, "utility_success": False}},
            {"case": "adaptive", "run": {**run, "duration_ms": 3.0}},
        ]
    )
    assert summary["attack_successes"] == 1 and summary["attack_trials"] == 2
    assert summary["adaptive_successes"] == 0 and summary["adaptive_trials"] == 1
    assert summary["normal_successes"] == 1 and summary["normal_trials"] == 1
    assert summary["p95_ms"] == 3.0
