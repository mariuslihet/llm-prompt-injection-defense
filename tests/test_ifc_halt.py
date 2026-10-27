from hypothesis import given
from hypothesis import strategies as st

from packages.ifc import Interpreter, Program, trusted_value
from packages.ifc.trace import ExecutionTrace
from tests.test_structural import POLICY


@given(
    before=st.integers(min_value=0, max_value=4),
    after=st.integers(min_value=1, max_value=5),
    mode=st.sampled_from(["enforce", "shadow"]),
)
def test_no_later_instructions_run_after_policy_denial(before, after, mode):
    summarize = {"op": "call", "tool": "summarize", "arguments": {"text": "document"}}
    denied = {"op": "call", "tool": "unknown", "arguments": {}}
    program = Program.model_validate(
        {"instructions": [summarize] * before + [denied] + [summarize] * after}
    )
    runtime = Interpreter(POLICY.model_copy(update={"mode": mode}), "alice")
    runtime.run(program, {"document": trusted_value("sample")})
    assert len(runtime.effects) == before
    assert len(runtime.trace) == before + 1
    assert not runtime.decisions[-1].allowed
    snapshot = runtime.snapshot()
    assert snapshot.halted_at == before and snapshot.skipped_instructions == after
    assert snapshot.steps[-1].decision and not snapshot.steps[-1].decision.allowed


def test_denial_does_not_undo_prior_effects_or_consume_later_grants():
    from packages.policy import Approvals, binding

    approvals = Approvals()
    args = {
        "recipient": trusted_value("team@example.invalid", sinks=frozenset({"send_email"})),
        "body": trusted_value("sample", sinks=frozenset({"send_email"})),
    }
    token = approvals.issue(binding("alice", POLICY, "send_email", args))
    program = Program.model_validate(
        {
            "instructions": [
                {"op": "call", "tool": "summarize", "arguments": {"text": "body"}},
                {"op": "call", "tool": "unknown", "arguments": {}},
                {
                    "op": "call",
                    "tool": "send_email",
                    "arguments": {"recipient": "recipient", "body": "body"},
                    "approval": token,
                },
            ]
        }
    )
    runtime = Interpreter(POLICY, "alice", approvals)
    runtime.run(program, args)
    assert runtime.effects == [("summarize", {"text": "sample"})]
    assert approvals.consume(token, binding("alice", POLICY, "send_email", args))


def test_halt_metadata_defaults_for_historical_traces_and_resets_per_run():
    old = ExecutionTrace.model_validate(
        {"policy_digest": POLICY.digest, "steps": [], "effect_count": 0}
    )
    assert old.halted_at is None and old.skipped_instructions == 0
    runtime = Interpreter(POLICY, "alice")
    runtime.run(
        Program.model_validate(
            {"instructions": [{"op": "call", "tool": "unknown", "arguments": {}}]}
        ),
        {},
    )
    assert runtime.snapshot().halted_at == 0
    runtime.run(Program.model_validate({"instructions": []}), {})
    assert runtime.snapshot().halted_at is None


def test_sequence_test_api_reports_stopped_and_prior_actions_without_external_effects():
    from tests.test_gateway import HEADERS, client

    with client() as c:
        body = {"document": "A sample report", "variant": "deny_first"}
        assert c.post("/ifc/sequence-test", json=body).status_code == 401
        first = c.post("/ifc/sequence-test", headers=HEADERS, json=body).json()
        assert first["trace"]["halted_at"] == 0
        assert first["trace"]["skipped_instructions"] == 1
        assert first["simulated_effects"] == []
        body["variant"] = "allow_then_deny"
        later = c.post("/ifc/sequence-test", headers=HEADERS, json=body).json()
        assert later["trace"]["halted_at"] == 1
        assert later["trace"]["skipped_instructions"] == 1
        assert [step["tool"] for step in later["trace"]["steps"]] == ["summarize", "send_email"]
        assert later["simulated_effects"] == [{"tool": "summarize", "text": "A sample report"}]
        assert all(step["decision"]["rule"] != "send_email" for step in later["trace"]["steps"][:1])
        audit = c.get("/audit", headers=HEADERS).json()["events"]
        assert "A sample report" not in str(audit)
    with client(role="viewer") as c:
        assert c.post("/ifc/sequence-test", headers=HEADERS, json=body).status_code == 403
