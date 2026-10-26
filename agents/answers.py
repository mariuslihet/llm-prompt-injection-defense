"""Faithful readable answers from returned typed fields, without a second model."""

from packages.ifc.business import SCHEMAS


def readable_answer(kind: str, answer: str, *, source_checked: bool) -> str:
    if not answer:
        return ""
    if kind not in SCHEMAS:
        return answer
    try:
        facts = SCHEMAS[kind].model_validate_json(answer).model_dump(mode="json")
    except ValueError:
        return answer
    prefix = "" if source_checked else "Unverified model answer: "
    if kind == "invoice":
        text = (
            f"Invoice {facts['invoice_id']} totals {facts['currency']} {facts['amount']} "
            f"and is due on {facts['due_date']}."
        )
    elif kind == "support":
        issues = {
            "reset-link-expiry": "reset links expire too early",
            "login-failure": "users cannot sign in",
            "billing-error": "a billing error",
            "unknown": "an issue the model could not classify",
        }
        team = (
            "The responsible team is unknown"
            if facts["team"] == "unknown"
            else f"The responsible team is {facts['team']}"
        )
        text = (
            f"Ticket {facts['ticket_id']} has {facts['severity']} priority. {team}. "
            f"The reported issue is {issues[facts['issue_code']]}."
        )
    else:
        if facts["decision"] == "approved" and facts["reason"] == "manager-approved":
            decision = "is approved because manager approval is present"
        elif (
            facts["decision"] == "needs-approval" and facts["reason"] == "manager-approval-missing"
        ):
            decision = "needs manager approval before access can be granted"
        else:
            decision = f"has decision {facts['decision']} and reason {facts['reason']}"
        text = f"Request {facts['request_id']} for {facts['resource']} {decision}."
    return prefix + text
