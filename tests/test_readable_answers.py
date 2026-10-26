import json

from agents.answers import readable_answer


def test_readable_answers_use_actual_returned_values_and_distinguish_unverified_output():
    facts = {
        "invoice_id": "INV-72",
        "amount": "123.45",
        "currency": "EUR",
        "due_date": "2026-12-01",
    }
    checked = readable_answer("invoice", json.dumps(facts), source_checked=True)
    assert "EUR 123.45" in checked and "2026-12-01" in checked and "INV-72" in checked
    unverified = readable_answer("invoice", json.dumps(facts), source_checked=False)
    assert unverified.startswith("Unverified model answer:")
    assert readable_answer("invoice", "", source_checked=True) == ""
    assert (
        readable_answer("invoice", "unstructured answer", source_checked=False)
        == "unstructured answer"
    )


def test_access_answers_do_not_confuse_approved_and_missing_approval():
    facts = {
        "request_id": "AR-72",
        "resource": "reporting",
        "decision": "approved",
        "reason": "manager-approved",
    }
    assert "is approved because manager approval is present" in readable_answer(
        "access", json.dumps(facts), source_checked=True
    )
    facts.update(decision="needs-approval", reason="manager-approval-missing")
    assert "needs manager approval" in readable_answer(
        "access", json.dumps(facts), source_checked=True
    )
