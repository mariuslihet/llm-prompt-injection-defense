# Tested security claims

These are conditional software invariants for the finite interpreter and the
two covered simulated external tools. They do not claim to prevent prompt injection.
Trusted computing base: label-assigning adapters, Python runtime, immutable value
operations, policy evaluator, interpreter, approval authority and simulated sink.
Direct modification of these components is outside the threat model.

| ID | Claim | Test reference |
| --- | --- | --- |
| C1 | An untrusted-derived value cannot set send_email.recipient, even with approval. | tests/test_structural.py::test_untrusted_recipient_never_reaches_email |
| C2 | A private-labeled argument cannot reach a covered external sink, even with approval. | tests/test_structural.py::test_private_egress_never_allowed |
| C3 | Concatenation joins provenance, reduces allowed sinks by intersection, and cannot raise trust or lower confidentiality. | tests/test_structural.py::test_join_never_increases_authority |
| C4 | Any untrusted input to an interpreter invocation requires approval before an otherwise permitted external call. | tests/test_structural.py::test_control_taint_and_valid_approval |
| C5 | An approval grant is tenant/policy/tool/argument/label-bound, expires and is consumed at most once. | tests/test_structural.py::test_approval_binding_single_use_tenant_policy_arguments_and_expiry; tests/test_gateway.py::test_human_approval_end_to_end_and_replay |
| C6 | Unknown tools, wrong argument shapes and external tools mislabeled as internal fail closed. | tests/test_structural.py::test_policy_fail_closed_and_static_verifier; tests/test_extensions.py::test_intrinsic_sink_and_taint_fallback |
| C7 | Quarantine extraction preserves labels; programs cannot overwrite prior values or invoke arbitrary Python. | tests/test_structural.py::test_interpreter_extraction_concat_unknowns_and_ssa |
| C8 | Within one interpreter invocation, no instruction after a denied tool call is executed. Earlier recorded effects are not rolled back. | tests/test_ifc_halt.py::test_no_later_instructions_run_after_policy_denial; tests/test_ifc_halt.py::test_denial_does_not_undo_prior_effects_or_consume_later_grants |

## Argument sketch

Induct on the bounded linear instruction sequence. Inputs obtain labels only
from trusted adapters. Extract copies its input label. Concat joins labels with
the least trust, greatest confidentiality and intersection of sink permissions.
Neither operation can overwrite an existing variable. Call resolves immutable
references and invokes the evaluator before adding a simulated effect. The evaluator
checks exact argument shape, intrinsic sink identity, trust, URL allowlist,
capability, confidentiality and invocation-wide untrusted control taint. A grant
can bypass only the final approval barrier. It cannot bypass the preceding
checks. Therefore C1-C4 hold for every reachable call in this DSL, assuming the
trusted computing base and the correctness of the label assignment.

For C8, the interpreter records the denied decision and terminates the instruction
loop before resolving any later call. A denial does not reverse earlier effects.
Use a fresh interpreter for each request; its history is cumulative if reused,
while halt metadata describes the most recent invocation.

The approval map is locked; consume atomically removes its token before checking
binding/expiry. A failed reuse cannot find the grant. A canonical policy hash and
canonical argument labels bind authorization to the reviewed action. The in-memory Approvals implementation revokes grants on restart. The gateway
uses transactional StateApprovals: token hashes, binding and expiry persist, and
atomic consumption is tested across two SQLite connections
(tests/test_persistence.py). Restart does not extend a grant or permit reuse.

## What the tests establish

Hypothesis samples strings and sink sets; it does not mathematically prove all
programs or detect every semantic leak. These arguments do not cover malicious
trusted adapters, encoded secret inference, external tool implementations or
distributed multi-host state. The gateway text proxy alone does not confer IFC: a client
must execute effects through the interpreter or the conservative taint fallback.

## Model-driven MVP boundary

The sample email runner dispatches only strict read_email/read_project/send_email/
finish schemas; it has no real external tool handle. Its model-driven planner
receives the trusted task without inbox content; quarantined output keeps its
untrusted label. Hostile tool names, missing references and forged approvals
fail closed in tests/test_email_agent.py. These are isolation and authorization
contracts, not a claim that a model can reason reliably or resist every attack.

## Record workflows and review queue

Scenario tools have exact scoped identifiers, and IFC adapters expose only the
scenario's read tools. Schema-valid extraction retains untrusted provenance; it
does not guarantee correct facts. Record-channel integrity attacks succeeded in
local model tests and are explicitly outside the authorization claims above.
Tests: tests/test_record_workflows.py.

Operator-originated approval reviews bind tenant, policy, arguments and labels;
expiry, role checks, atomic claim and single-use grant consumption precede a
simulated effect. Restart marks executing reviews interrupted without retry.
Tests: tests/test_review_queue.py and tests/test_restore_rehearsal.py. This is
a single-worker SQLite contract, not a distributed exactly-once guarantee.


## C6: source agreement for configured record workflows

With source checks enforced, a successful covered full-IFC run returns the
canonical fields derived by packages/ifc/grounding.py from its scoped adapter
observations. Missing, invalid or mismatched evidence withholds the answer.
Invoice/vendor linkage, typed incident impact and manager approval use fixed
server-side rules; untrusted notes cannot redefine them. All proposal/evidence
labels are joined conservatively. Final-program changes to canonical output fail
closed. Tests: tests/test_grounding.py (including property tests, changed sources,
private labels, all 30 cases and post-check rewriting).

Argument: successful typed reads determine the finite canonical field set;
model proposals only contribute comparison evidence. Enforce substitutes that
canonical value, joins all input labels, then requires the final successful
program answer to preserve its serialization. Exceptions withhold the answer.
Therefore returned fields agree with the configured source resolver under the
trusted-adapter/source-schema assumptions. This does not establish source truth,
protection against corrupted authoritative fields, or coverage of arbitrary text
tasks. Off/shadow modes do not establish this claim.
