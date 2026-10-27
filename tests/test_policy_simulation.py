from copy import deepcopy

import pytest

from tests.test_gateway import HEADERS, client


def intent():
    return {
        "tool": "send_email",
        "untrusted_context": True,
        "arguments": {
            "recipient": {
                "value": "team@example.invalid",
                "origin": "trusted",
                "sink_allowed": True,
            },
            "body": {"value": "sample summary", "origin": "untrusted", "sink_allowed": True},
        },
    }


def test_policy_simulation_shows_approval_effect_without_issuing_a_grant():
    with client() as c:
        body = intent()
        assert c.post("/policy/simulate", json=body).status_code == 401
        response = c.post("/policy/simulate", headers=HEADERS, json=body)
        assert response.status_code == 200
        result = response.json()
        assert result["without_approval"]["needs_approval"]
        assert not result["without_approval"]["allowed"]
        assert result["with_approval"]["allowed"]
        assert result["simulated"] and "no approval is issued" in result["scope"]
        assert "approval" not in result and "effects" not in result
        audit = c.get("/audit", headers=HEADERS).json()["events"]
        assert len(audit) == 1 and audit[0]["event"]["action"] == "simulate"
        assert "sample summary" not in str(audit) and "team@example.invalid" not in str(audit)


@pytest.mark.parametrize(
    ("field", "updates", "reason"),
    [
        ("recipient", {"origin": "untrusted"}, "untrusted destination"),
        ("body", {"origin": "private"}, "private egress"),
        ("body", {"origin": "untrusted", "private": True}, "private egress"),
        ("body", {"sink_allowed": False}, "sink capability missing"),
    ],
)
def test_hypothetical_approval_does_not_override_structural_denials(field, updates, reason):
    body = deepcopy(intent())
    body["arguments"][field].update(updates)
    with client() as c:
        result = c.post("/policy/simulate", headers=HEADERS, json=body).json()
        assert not result["without_approval"]["allowed"]
        assert not result["with_approval"]["allowed"]
        assert reason in result["with_approval"]["reason"]


def test_policy_simulation_applies_url_allowlist_and_rejects_invalid_shapes():
    body = {
        "tool": "fetch_url",
        "untrusted_context": False,
        "arguments": {
            "url": {
                "value": "https://docs.example.invalid/report",
                "origin": "trusted",
                "sink_allowed": True,
            }
        },
    }
    with client(role="viewer") as c:
        assert c.post("/policy/simulate", headers=HEADERS, json=body).json()["without_approval"][
            "allowed"
        ]
        body["arguments"]["url"]["value"] = "https://collector.example.invalid/report"
        result = c.post("/policy/simulate", headers=HEADERS, json=body).json()
        assert not result["with_approval"]["allowed"]
        assert "URL denied" in result["with_approval"]["reason"]
        body["arguments"]["extra"] = body["arguments"]["url"]
        assert c.post("/policy/simulate", headers=HEADERS, json=body).status_code == 422
