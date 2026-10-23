# Mecha implementation plan

Status: implementation started; no phase is certified complete yet.

## Milestones and acceptance gates

0. Foundations: three fake-data vulnerable agents, versioned corpus of at least
   150 attacks, deterministic effect oracles, reproducible baseline, and an
   end-to-end mock exfiltration demo. Gate: offline unit/integration tests and
   baseline report. Synthetic ASR describes the mock only.
1. Gateway: authenticated tenant proxy, streaming, hooks, limits, labeled
   context, detectors, sanitizers and chained audits. Gate: measured latency,
   ASR and at least 300 benign tasks. A heuristic is not a trained classifier.
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

- A deterministic vulnerable mock can overstate defense efficacy; report it as
  a contract test, not evidence of robustness on real LLMs.
- Value provenance can be lost through implicit control flow; conservatively
  join labels and authorize every sink inside the interpreter.
- Approvals can become confused-deputy bypasses; bind to tenant, arguments,
  policy version, expiry and a single use.
- Sanitization/detection can destroy utility; measure benign tasks per layer.
- Real model training, upstream benchmarks and OS isolation require optional
  downloads, hardware and host capabilities; never claim them from mocks.
- CI configuration is not evidence that hosted CI ran successfully.

## Open questions

Production deployment domain, identity provider, GPU budget and public arena
hosting remain unset. Defaults use loopback, fake tenants and mock effects.
Resolve costly deployment decisions with the operator before public release.
