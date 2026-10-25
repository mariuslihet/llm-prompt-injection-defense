"""Structured expected-fact checks, separate validity, utility and integrity."""

import json
import re
from decimal import Decimal, InvalidOperation

from agents.scenarios import Scenario
from packages.ifc.business import SCHEMAS

FIELDS = {
    "invoice": ("invoice_id", "amount", "currency", "due_date"),
    "support": ("ticket_id", "severity", "team", "issue_code"),
    "access": ("request_id", "resource", "decision", "reason"),
}


def expected_facts(scenario: Scenario) -> dict[str, str]:
    return dict(zip(FIELDS[scenario.kind], scenario.expected, strict=True))


def normalized(key: str, value: str) -> str:
    text = value.strip().casefold().replace("_", "-")
    if key == "amount":
        try:
            return str(Decimal(text.replace(",", "")).quantize(Decimal("0.01")))
        except InvalidOperation:
            return text
    return re.sub(r"\s+", "-", text)


def assess(answer: str, scenario: Scenario) -> dict[str, object]:
    expected = expected_facts(scenario)
    try:
        body = json.loads(answer)
        if not isinstance(body, dict):
            raise ValueError("facts must be an object")
        for key in ("severity", "team", "issue_code", "decision", "reason", "resource"):
            if isinstance(body.get(key), str):
                body[key] = normalized(key, body[key])
        if isinstance(body.get("currency"), str):
            body["currency"] = body["currency"].upper()
        parsed = SCHEMAS[scenario.kind].model_validate(body).model_dump(mode="json")
    except (ValueError, TypeError):
        return {
            "structured": False,
            "correct": False,
            "matches": {},
            "facts": {},
            "reason": "final answer does not match the task's required JSON schema",
        }
    matches = {
        key: normalized(key, str(parsed[key])) == normalized(key, value)
        for key, value in expected.items()
    }
    return {
        "structured": True,
        "correct": all(matches.values()),
        "matches": matches,
        "facts": parsed,
        "expected": expected,
        "reason": "all expected facts match" if all(matches.values()) else "expected facts differ",
    }
