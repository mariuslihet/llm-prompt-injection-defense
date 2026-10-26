# Mecha implementation plan

Status: implementation started; no phase is certified complete yet.

## Private MVP increment (2026-10-24)

1. Replace fixture-only evidence with a natural-language email agent, strict
   model action loop, sample private memo and observable sample email effects.
2. Compare baseline, prompt hardening, detector, detector + sanitizer and IFC;
   run an adaptive model attacker with explicit call/turn/time budgets and
   paired normal-task cases. Invalid model outputs are measured as errors.
3. Add authenticated durable background jobs, tenant-scoped status/results,
   cancellation, restart recovery, queue bounds and a dashboard run interface.
4. Harden provider configuration/response bounds, startup validation, API
   errors, browser headers, readiness and operational documentation.
5. Run local contracts, coverage, builds, dependency checks and a real local
   model smoke. Update acceptance status honestly. Keep publication and live
   Linux verification deferred per operator choice. ADR-0007 defines scope.

## Milestones and acceptance gates

0. Foundations: three sample-data vulnerable agents, versioned corpus of at least
   150 attacks, deterministic effect oracles, reproducible baseline, and an
   end-to-end simulated exfiltration demo. Gate: offline unit/integration tests and
   baseline report. Synthetic ASR describes the simulated only.
1. Gateway: authenticated tenant proxy, streaming, hooks, limits, labeled
   context, detectors, sanitizers and chained audits. Gate: measured latency,
   ASR and at least 300 normal-task tasks. A heuristic is not a trained classifier.
2. Structural control: propagating labels, restricted planner interpreter,
   quarantined extraction, capabilities, per-argument policy, approvals and
   static verification. Gate: property tests for explicit claims, denied
   exfiltration/tool abuse, measured utility and coverage >=85% on core modules.
3. Evaluation: seeded static/adaptive campaigns, ablations, confidence intervals,
   JSON/HTML reports and CI gates. External benchmark adapters must distinguish
   fixture smoke tests from upstream benchmark execution.
4. Research: individually reproducible training/probe/hierarchy experiments,
   MCP definition integrity, memory and multimodal experiments, real isolation.
   Gate: measured results including failures; unavailable models/hardware are
   recorded as not run, never replaced by invented scores.
5. Release: dashboard, safe arena, SDKs, deploy assets, operational docs and
   clean-machine quickstart. Gate: CI green, deployment verified, report
   published, signed release and independent quickstart timing.

## Execution

Implement small, independently checked increments and conventional commits.
Every increment records actual commands/results in docs/reports. Keep the
project folder name requested by the operator; packages follow the requested
layout without an extra sentry directory (ADR-0001).

## Risks

- A deterministic vulnerable simulated can overstate defense efficacy; report it as
  a contract test, not evidence of robustness on real LLMs.
- Value provenance can be lost through implicit control flow; conservatively
  join labels and authorize every sink inside the interpreter.
- Approvals can become confused-deputy bypasses; bind to tenant, arguments,
  policy version, expiry and a single use.
- Sanitization/detection can destroy utility; measure normal-task tasks per layer.
- Real model training, upstream benchmarks and OS isolation require optional
  downloads, hardware and host capabilities; never claim them from mocks.
- CI configuration is not evidence that hosted CI ran successfully.

## Open questions

Production deployment domain, identity provider, GPU budget and public arena
hosting remain unset. Defaults use loopback, sample tenants and simulated effects.
Resolve costly deployment decisions with the operator before public release.

## Current increment — 2026-10-25

1. Distinct scoped record workflows and typed state changes.
2. Exfiltration, integrity and per-run memory attacks with structured outcomes.
3. Versioned development/held-out cases and matched comparisons.
4. Durable tenant-scoped human review of otherwise permitted actions.
5. Local restore rehearsal and fresh durable-load measurements.

Acceptance: offline regression/property checks, live local-model evidence and
visible UI verification. Keep failures explicit and leave all changes unstaged.
External Linux/deployment validation remains deferred.


## Review and evaluation workspace expansion

Implement bounded review metadata/history, notes and withdrawal; focused defense
selection, named runs, saved-setup reuse, outcome/tool summaries and safe CSV
exports. Verify tenant isolation, transitions and browser flows (ADR-0011).
Keep all work local and unstaged; no new dependencies are needed.


## Source-grounded answers — 2026-10-26

Add typed source checks for the three record workflows, preserve field-level
proposal/source evidence and label joins, fail closed on missing/conflicting
records, and compare off/shadow/enforce modes. Measure real local static and
adaptive attacks with utility, then expose understandable explanations in the
console. No new dependencies or Git mutations. Boundary and assumptions: ADR-0012.
