from pathlib import Path

import pytest

from packages.ifc import Interpreter, Program, trusted_value, untrusted_value
from packages.ifc.analysis import analyze
from packages.policy import compile_policy

POLICY = compile_policy(Path("packages/policy/default.yaml").read_text())


def program():
    return Program.model_validate(
        {
            "instructions": [
                {"op": "extract", "source": "document", "output": "summary"},
                {"op": "concat", "left": "private", "right": "summary", "output": "body"},
                {
                    "op": "call",
                    "tool": "send_email",
                    "arguments": {"recipient": "recipient", "body": "body"},
                },
            ]
        }
    )


def inputs():
    return {
        "document": untrusted_value("attacker data"),
        "private": trusted_value("fake private", private=True),
        "recipient": trusted_value("team@example.invalid", sinks=frozenset({"send_email"})),
    }


def test_graph_reports_trifecta_paths_and_enforced_boundaries_without_effects():
    report = analyze(program(), inputs(), POLICY)
    assert report.private_paths and report.untrusted_paths
    assert report.private_paths[0].sink == report.untrusted_paths[0].sink
    assert report.guarded_sinks and not report.violations
    assert ("document", "summary") in report.edges and ("private", "body") in report.edges


def test_unsafe_policy_graph_fails_verification_and_unknown_tools_are_reported():
    unsafe = POLICY.model_copy(
        update={
            "rules": tuple(
                rule.model_copy(
                    update={"trusted_arguments": frozenset(), "approval_after_untrusted": False}
                )
                for rule in POLICY.rules
            )
        }
    )
    assert analyze(program(), inputs(), unsafe).violations
    unknown = Program.model_validate(
        {"instructions": [{"op": "call", "tool": "unknown", "arguments": {}}]}
    )
    assert analyze(unknown, {}, POLICY).violations


def test_bad_later_reference_never_allows_earlier_effect():
    proposed = Program.model_validate(
        {
            "instructions": [
                {"op": "call", "tool": "summarize", "arguments": {"text": "document"}},
                {"op": "extract", "source": "missing", "output": "bad"},
            ]
        }
    )
    runtime = Interpreter(POLICY, "alice")
    with pytest.raises(KeyError):
        runtime.run(proposed, inputs())
    assert not runtime.effects
