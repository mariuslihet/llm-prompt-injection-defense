from pathlib import Path

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from packages.core import Confidentiality, Label, Trust
from packages.ifc import Interpreter, Program, plan, trusted_value, untrusted_value
from packages.policy import Approvals, binding, compile_policy, evaluate, verify
from packages.sanitizers import sanitize

POLICY = compile_policy(Path("packages/policy/default.yaml").read_text())
SINKS = frozenset({"send_email"})


@given(st.text(max_size=200), st.text(max_size=200))
def test_untrusted_recipient_never_reaches_email(a, b):
    args = {"recipient": untrusted_value(a), "body": trusted_value(b, sinks=SINKS)}
    for approved in (False, True):
        assert not evaluate(
            POLICY, "send_email", args, read_untrusted=True, approved=approved
        ).allowed


@given(st.text(max_size=200))
def test_private_egress_never_allowed(text):
    args = {
        "recipient": trusted_value("person@example.invalid", sinks=SINKS),
        "body": trusted_value(text, private=True, sinks=SINKS),
    }
    assert not evaluate(POLICY, "send_email", args, read_untrusted=False, approved=True).allowed


@given(
    st.sets(st.sampled_from(["send_email", "fetch_url", "summarize"])),
    st.sets(st.sampled_from(["send_email", "fetch_url", "summarize"])),
)
def test_join_never_increases_authority(left, right):
    a = Label(sources=frozenset({"user"}), trust=Trust.TRUSTED, allowed_sinks=frozenset(left))
    b = Label(
        sources=frozenset({"web"}),
        trust=Trust.UNTRUSTED,
        confidentiality=Confidentiality.PRIVATE,
        allowed_sinks=frozenset(right),
    )
    joined = a.join(b)
    assert joined.trust == Trust.UNTRUSTED
    assert joined.confidentiality == Confidentiality.PRIVATE
    assert joined.allowed_sinks <= a.allowed_sinks & b.allowed_sinks
    assert joined.sources == a.sources | b.sources
    assert a.join(b) == b.join(a)


def test_approval_binding_single_use_tenant_policy_arguments_and_expiry(monkeypatch):
    approvals = Approvals()
    args = {
        "recipient": trusted_value("person@example.invalid", sinks=SINKS),
        "body": trusted_value("Public summary", sinks=SINKS),
    }
    expected = binding("alice", POLICY, "send_email", args)
    token = approvals.issue(expected)
    assert not approvals.consume(token, binding("bob", POLICY, "send_email", args))
    assert not approvals.consume(token, expected)
    token = approvals.issue(expected)
    assert approvals.consume(token, expected)
    assert not approvals.consume(token, expected)
    monkeypatch.setattr("packages.policy.time.monotonic", lambda: 100.0)
    token = approvals.issue(expected, ttl=1)
    monkeypatch.setattr("packages.policy.time.monotonic", lambda: 102.0)
    assert not approvals.consume(token, expected)
    with pytest.raises(ValueError):
        approvals.issue(expected, ttl=0)


def test_control_taint_and_valid_approval():
    args = {
        "recipient": trusted_value("person@example.invalid", sinks=SINKS),
        "body": trusted_value("Public summary", sinks=SINKS),
    }
    approvals = Approvals()
    runtime = Interpreter(POLICY, "alice", approvals)
    program = {
        "instructions": [
            {
                "op": "call",
                "tool": "send_email",
                "arguments": {"recipient": "recipient", "body": "body"},
            }
        ]
    }
    runtime.run(Program.model_validate(program), {**args, "unused": untrusted_value("hello")})
    assert not runtime.effects
    assert runtime.decisions[-1].needs_approval
    program["instructions"][0]["approval"] = approvals.issue(
        binding("alice", POLICY, "send_email", args)
    )
    runtime.run(Program.model_validate(program), {**args, "unused": untrusted_value("hello")})
    assert len(runtime.effects) == 1


def test_interpreter_extraction_concat_unknowns_and_ssa():
    runtime = Interpreter(POLICY, "alice")
    values = runtime.run(plan("summarize"), {"document": untrusted_value("data")})
    assert values["summary"].label == values["document"].label
    assert runtime.effects == [("summarize", {"text": "data"})]
    concat = Program.model_validate(
        {"instructions": [{"op": "concat", "left": "a", "right": "b", "output": "c"}]}
    )
    values = runtime.run(concat, {"a": trusted_value("a"), "b": untrusted_value("b")})
    assert values["c"].data == "ab" and values["c"].label.trust == Trust.UNTRUSTED
    with pytest.raises(ValueError):
        runtime.run(concat, {**values})
    with pytest.raises(KeyError):
        runtime.run(concat, {})
    with pytest.raises(ValidationError):
        Program.model_validate({"instructions": [{"op": "exec", "code": "print(1)"}]})
    with pytest.raises(ValidationError):
        values["c"].label.trust = Trust.TRUSTED


def test_policy_fail_closed_and_static_verifier():
    assert not verify(POLICY)
    assert not evaluate(POLICY, "unknown", {}, read_untrusted=False).allowed
    assert not evaluate(POLICY, "send_email", {}, read_untrusted=False).allowed
    bad = compile_policy(
        'version: "1"\nrules:\n- tool: send_email\n  arguments: [recipient, body]\n'
        "  external: true\n  approval_after_untrusted: false"
    )
    assert len(verify(bad)) == 2
    for text in (
        "!!python/object:os.system {}",
        'version: "1"\nrules: []\nunknown: 1',
        'version: "1"\nrules:\n- tool: a\n  arguments: [x]\n  trusted_arguments: [y]',
        'version: "1"\nrules:\n- {tool: a, arguments: [x]}\n- {tool: a, arguments: [x]}',
        "a" * 65537,
    ):
        with pytest.raises((ValueError, yaml.YAMLError)):
            compile_policy(text)


@pytest.mark.parametrize(
    "url",
    [
        "http://docs.example.invalid",
        "https://docs.example.invalid.evil.invalid",
        "https://evil.invalid@docs.example.invalid",
        "https://docs.example.invalid:444",
        "https://[broken",
        "https://docs.example.invalid\\evil",
        "https://docs.example.invalid/\nsecret",
    ],
)
def test_url_policy_rejects_ambiguous_destinations(url):
    args = {"url": trusted_value(url, sinks=frozenset({"fetch_url"}))}
    assert not evaluate(POLICY, "fetch_url", args, read_untrusted=False).allowed


def test_capabilities_shadow_and_allowed_url():
    args = {"url": trusted_value("https://docs.example.invalid", sinks=frozenset({"fetch_url"}))}
    assert evaluate(POLICY, "fetch_url", args, read_untrusted=False).allowed
    assert not evaluate(
        POLICY, "fetch_url", {"url": trusted_value(args["url"].data)}, read_untrusted=False
    ).allowed
    runtime = Interpreter(POLICY.model_copy(update={"mode": "shadow"}), "alice")
    runtime.run(
        Program.model_validate(
            {"instructions": [{"op": "call", "tool": "unknown", "arguments": {}}]}
        ),
        {},
    )
    assert not runtime.effects and runtime.shadow_decisions


@given(st.text(max_size=100))
def test_canary_and_unicode_are_removed(prefix):
    result = sanitize(prefix + " FAKE_PRIVATE_CANARY_MECHA_7f82\u202e")
    assert "FAKE_PRIVATE_CANARY_MECHA_7f82" not in result.text
    assert "\u202e" not in result.text


def test_sanitizer_images_html_links_and_pii():
    value = sanitize(
        "![x](https://evil.example.invalid/x) <img src=x> person@example.invalid "
        "https://docs.example.invalid/doc SECRET",
        frozenset({"docs.example.invalid"}),
        ("SECRET",),
    )
    assert "[IMAGE-BLOCKED]" in value.text
    assert "<img" not in value.text and "person@" not in value.text
    assert "https://docs.example.invalid/doc" in value.text and "SECRET" not in value.text
    assert {"markdown-image", "html-escaped", "pii-email", "configured-secret"} <= set(
        value.findings
    )
