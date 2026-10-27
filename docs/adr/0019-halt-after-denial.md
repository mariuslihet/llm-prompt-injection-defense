# ADR 0019: halt a restricted program after denial

Accepted 2026-10-27. When a policy evaluator denies a tool call, the bounded
interpreter records the decision and stops the current instruction sequence.
Later transforms, calls and approval consumption do not occur. The same rule
applies in shadow mode, which already does not execute denied sandbox calls.

This changes behavior for programs that previously continued after denial.
Earlier effects cannot be assumed reversible and remain recorded; this is not
transactional rollback or an exactly-once guarantee. Trace metadata records the
zero-based halt position and number of skipped instructions. A bounded tool name
is recorded for known tools; arbitrary model-provided names are represented as
`other`, keeping raw text out of audit. Historical traces omit the new optional
fields and remain readable. A fresh interpreter is expected per request; reused
instances retain history, while halt metadata describes the latest invocation.

Expose two fixed sample sequences through the authenticated Security Tests UI
and API. They use only repository-owned simulated tools and issue no approval.
The test never accepts arbitrary programs or tool names from the client. No new
dependencies were added.
