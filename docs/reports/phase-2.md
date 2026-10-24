# Phase 2: structural core

Built immutable provenance/trust/confidentiality/sink labels, conservative joins,
restricted linear programs, a no-tools typed extractor, per-argument YAML rules,
finite static verification, opaque bound single-use approvals, and shadow traces
that cannot disable structural enforcement. Private values and untrusted
destinations remain denied even with approval. ADR 0002 explains the utility tradeoff.

Hypothesis properties cover destination taint, private egress, label joins and
canary removal. Integration tests cover control taint, approval replay, tenant
binding, unknown instructions and label overwrite. See SECURITY_CLAIMS.md.

Measured synthetic static and adaptive ASR: 0/504 per campaign. Normal-task fixture
utility: 280/336 (83.33%). All 56 external-delivery tasks lack the required
approval/capability after untrusted extraction, so they fail. This cost is
reported rather than counted as successful blocking. Exact per-layer metrics
and category counts are in latest.json.

Not accepted as complete: real LLM planner/quarantine execution, general
data-flow analysis, distributed approvals and real-tool security evidence.

Update 2026-10-24: added finite source/transform/sink graph analysis, full-program
reference preflight before effects, persistent bound approvals, typed trace
snapshots, and opt-in model planner/quarantine boundaries. The natural-language
email MVP exercises these boundaries; arbitrary programs and multi-host
production state remain outside the verified scope.
