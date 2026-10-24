from contextlib import nullcontext

import pytest

from packages.telemetry import Audit
from packages.telemetry.otel import emit
from tests.test_gateway import HEADERS, client


def test_trace_export_does_not_include_prompt_or_audit_trace_contents(monkeypatch):
    pytest.importorskip("opentelemetry.trace")
    collected = []

    class Tracer:
        def start_as_current_span(self, name, attributes):
            collected.append((name, attributes))
            return nullcontext()

    monkeypatch.setattr("opentelemetry.trace.get_tracer", lambda name: Tracer())
    emit(
        {
            "action": "block",
            "rule": "ifc",
            "trace": "FAKE_SECRET_CONTENT",
            "reason": "FAKE_PRIVATE_DATA",
        }
    )
    assert collected == [("security.decision", {"mecha.action": "block", "mecha.rule": "ifc"})]


def test_touching_mcp_honeytool_is_denied_and_audited_high_severity():
    with client() as c:
        response = c.post(
            "/mcp",
            headers=HEADERS,
            json={
                "id": 1,
                "method": "tools/call",
                "params": {"name": "export_all_private_data", "arguments": {}},
            },
        )
        assert "error" in response.json()
        event = c.get("/audit", headers=HEADERS).json()["events"][0]["event"]
        assert event["severity"] == "high" and event["action"] == "block"


def test_severity_is_validated():
    with pytest.raises(ValueError):
        Audit().append("fake", {"action": "block", "severity": "arbitrary payload"})
