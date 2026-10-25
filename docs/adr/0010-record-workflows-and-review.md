# ADR 0010: record workflows, integrity evaluation and human review

Accepted 2026-10-25 for the private local MVP.

Use distinct, scenario-scoped finance, support and access-review read tools.
Unsafe configurations can mutate isolated per-run sample records. IFC receives
only server-scoped reads through trusted adapters; extracted values retain their
untrusted labels. Unknown state-changing tools remain default-denied.

Keep expected facts outside attacker input. Schema-checked outcomes distinguish
utility, confidentiality, integrity and execution validity. Versioned development
and held-out cases have disjoint identifiers; a small authored held-out set is
not independent external validation. Preserve prior evidence and fingerprints.

Human approval applies only to otherwise permitted operator-originated actions,
bound to tenant, policy, values and labels. Review does not authorize private
egress or model-originated destinations. Effects remain simulated.

No new dependency is needed. Verify local backup/restore and bounded load;
Linux deployment/isolation checks remain deferred by operator instruction.

Completion requires scoped sources and the public output schema within the existing
turn limit. Recovery reveals no expected facts. Suite call allocation reserves
30 × max(2, turn limit), at most 240 calls, to cover every bounded execution;
campaigns retain 128 calls and all jobs retain the 600-second deadline.
Inspecting held-out failures makes those cases development evidence thereafter.
