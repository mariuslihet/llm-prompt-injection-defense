# Changelog

## 0.2.0 — private MVP candidate, 2026-10-24

- Model-driven natural-language email agent with strict actions, sample inbox,
  private memo and email ledger. No real outbound tool exists.
- Planner/data separation with typed meeting facts, provenance-preserving
  quarantine and interpreter authorization. Invalid model actions consume a
  bounded retry budget and never execute.
- Adaptive model-attacker comparison across five defenses, paired normal-task cases,
  exact sample inputs, model/source hashes and explicit invalid-run counts.
- Durable tenant-isolated jobs, idempotency, quotas, cancellation with partial
  evidence, restart interruption and exclusive production worker locking.
- Agent Lab timelines, detailed fixture Arena, result downloads and same-origin
  built console serving; Python/TypeScript job SDK methods.
- Persistent local control state, typed incident replay, aggregate metrics,
  optional Ed25519 catalog signatures/external audit anchors, bounded MCP and
  DNS-pinned egress transports, and bounded gVisor command wrapper.
- Measured classifier, transformer feedback rounds, bounded DPO and hidden
  PDF/PNG experiments, including failed behavior probes and negative results.

This candidate is private and locally verified. Production release gates remain
open: deployment/isolation verification, durable high-concurrency latency,
representative held-out model evaluation and independent security review.
No public release, license selection or production certification is implied.
