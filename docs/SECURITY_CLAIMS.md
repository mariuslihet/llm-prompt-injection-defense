# Tested security claims

These are conditional software invariants for the finite interpreter and the
two covered mock external tools. They do not claim to prevent prompt injection.
Trusted computing base: label-assigning adapters, Python runtime, immutable value
operations, policy evaluator, interpreter, approval authority and mock sink.
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

## Argument sketch

Induct on the bounded linear instruction sequence. Inputs obtain labels only
from trusted adapters. Extract copies its input label. Concat joins labels with
the least trust, greatest confidentiality and intersection of sink permissions.
Neither operation can overwrite an existing variable. Call resolves immutable
references and invokes the evaluator before adding a mock effect. The evaluator
checks exact argument shape, intrinsic sink identity, trust, URL allowlist,
capability, confidentiality and invocation-wide untrusted control taint. A grant
can bypass only the final approval barrier. It cannot bypass the preceding
checks. Therefore C1-C4 hold for every reachable call in this DSL, assuming the
trusted computing base and the correctness of the label assignment.

The approval map is locked; consume atomically removes its token before checking
binding/expiry. A failed reuse cannot find the grant. A canonical policy hash and
canonical argument labels bind authorization to the reviewed action. Restart
revokes every outstanding grant. This establishes C5 within one process.

## What the tests establish

Hypothesis samples strings and sink sets; it does not mathematically prove all
programs or detect every semantic leak. These arguments do not cover malicious
trusted adapters, encoded secret inference, external tool implementations or
distributed state. The gateway text proxy alone does not confer IFC: a client
must execute effects through the interpreter or the conservative taint fallback.
