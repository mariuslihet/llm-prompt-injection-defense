# ADR 0002: Bounded linear IFC programs and strict approvals

Accepted. Programs contain extract, concat and call operations with immutable
single-assignment values. There is no dynamic Python execution, branching or
tool access from quarantine. Planner literals are supplied by trusted adapters;
remote clients cannot assert trust labels. Unknown operations/arguments fail.
Implicit control flow is conservatively tainted by any untrusted input.

Private values can never leave via an external tool, even with approval.
Untrusted destinations can never receive capability through approval. Human
approval only clears the after-untrusted-read barrier for otherwise permitted
arguments. This is stricter than declassification and may reduce utility.

Shadow mode records decisions without allowing forbidden mock effects. There
is no production rollout switch that disables structural invariants. Current
approvals are request-process local; restart revokes them. A distributed
deployment requires a transactional shared grant store before enabling writes.
