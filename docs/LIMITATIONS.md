# Limitations and unvalidated requirements

Mecha is a working offline research prototype, not a certified production
security boundary or a claim of general prompt-injection prevention.

- The 168 attacks share a synthetic command grammar and three agents share the
  same unsafe follower. Fixture ASR cannot predict real-model ASR. Template
  trials are correlated, so Wilson intervals are descriptive only.
- The 336 benign tasks vary fixture content and task type, not real reasoning
  complexity. IFC utility is lower because unapproved external delivery fails.
- Gateway compatibility is a supported text subset: no vision/audio/tool-call
  transport forwarding, client-controlled system prompts or genuine incremental
  provider streaming. Output is buffered before sanitized SSE delivery. Reported
  token counts are unavailable (zero), and cost is measured only for mocks.
- Probabilistic classifier/judge thresholds are not calibrated on a real model.
  Heuristic scores are not probabilities. Text sanitization cannot undo effects.
- Approval and rate-limit state are process-local. Use a single worker; multiple
  replicas require transactional shared state. Raw /tools/call arguments are
  explicit authenticated operator intent, never a safe adapter for model output.
- SQLite chaining detects modified chain content, not deletion/replacement of
  the entire database. Export a signed external chain anchor for stronger evidence.
- Static verification checks the finite declared tool AST and known sink classes;
  it is not whole-program analysis of arbitrary Python or external tool internals.
- No upstream benchmark executions, real-provider runs, GPU training, live MCP
  interoperability or public deployment have been certified. Local export
  adapters require explicit upstream field normalization and execution mapping.
- Real OS isolation requires Linux with runsc or Firecracker. Docker assets and
  Helm templates are not proof that those runtimes were installed or tested.
- No public arena, external webhook delivery, signed release or hosted CI run is
  asserted by the presence of source/configuration files. Release requires the
  requirements checklist and phase-specific acceptance evidence.
