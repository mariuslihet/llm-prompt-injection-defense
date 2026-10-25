# Limitations and unvalidated requirements

Mecha is a working offline research prototype, not a certified production
security boundary or a claim of general prompt-injection prevention.

- The 168 attacks share a synthetic command grammar and three agents share the
  same unsafe follower. Fixture ASR cannot predict real-model ASR. Template
  trials are correlated, so Wilson intervals are descriptive only.
- The 336 normal-task tasks vary fixture content and task type, not real reasoning
  complexity. IFC utility is lower because unapproved external delivery fails.
- Gateway compatibility is a supported text subset: no vision/audio/tool-call
  transport forwarding, client-controlled system prompts or genuine incremental
  provider streaming. Output is buffered before sanitized SSE delivery. Reported
  token counts are unavailable (zero), and cost is measured only for mocks.
- The BERT classifier is calibrated on grouped synthetic fixtures; it is not
  calibrated for general agent behavior. The optional judge lacks representative
  calibration. Heuristic scores are not probabilities. Text sanitation cannot
  undo tool effects. Self-play increased normal-task false positives without measured
  evasion improvement. The four-step DPO run showed no preference gain.
- SQLite persists approvals, limits, tenants, policies, sample review data and
  jobs. Use a single worker on one host; Postgres/distributed execution is absent.
  Outstanding grants remain bound and expiring after restart. Raw /tools/call arguments are
  explicit authenticated operator intent, never a safe adapter for model output.
- A bare SQLite chain cannot detect complete deletion/replacement. Optional
  Ed25519 external anchors detect loss/change of their anchored prefix only when
  the operator preserves the signed anchor and trusted key outside the database.
- Static verification checks the finite declared tool AST and known sink classes;
  it is not whole-program analysis of arbitrary Python or external tool internals.
- No upstream benchmark executions, external-provider runs, GPU training, live MCP
  interoperability or public deployment have been certified. Local export
  adapters require explicit upstream field normalization and execution mapping.
- Real OS isolation requires Linux with runsc or Firecracker. Docker assets and
  Helm templates are not proof that those runtimes were installed or tested.
- No public arena, external webhook delivery, signed release or hosted CI run is
  asserted by the presence of source/configuration files. Release requires the
  requirements checklist and phase-specific acceptance evidence.

The natural-language Agent Lab executes real model responses with sample email
tools. A small scenario and a model-generated attacker are not a comprehensive
benchmark. The 135M local model produced invalid actions; that is inconclusive.
Model transcript storage is restricted by design to sample-data jobs, not general
customer requests. Local inference has a generation bound but no hard process
isolation. The installed CPU model is not a production throughput guarantee.

Production readiness is blocked by the open gates in docs/MVP.md. The durable
Windows localhost concurrency-16 p95 target failed. No license/public release
is added, as the operator chose to keep the repository private.

## Record workflow validation (2026-10-25)

The Qwen2.5-7B-Instruct local GPU runner now exercises distinct scoped read tools
and isolated state changes. A locally authored 15/15 development/held-out split
contains 30 task instances; inspecting held-out failures during development means
it is not a pristine external validation set. Initial runs skipped required tools;
completion now requires the sources and task schema within the same turn budget.
No expected values are supplied by recovery prompts. Schema validity does not
establish truth: full IFC suffered 2/3 answer-integrity successes in the new
record-channel test, while blocking unauthorized tool authority. These results
restrict the claims; they are not evidence of general integrity protection.

The latest durable loopback load test recorded p95 348.90 ms at concurrency 16
(1,000 requests, zero HTTP errors); the 50 ms end-to-end gate remains failed.
Server-only p95 was 11.712 ms and cannot substitute for end-to-end acceptance.
Restore rehearsal verified each SQLite snapshot independently, not an atomic
cross-database recovery or a production service cutover.
