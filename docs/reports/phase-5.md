# Phase 5: local console and release preparation

Built React/Vite dashboard and shared-stack arena frontend: tenant audit
inspection, policy YAML validation, staging/history/activation/rollback, and
platform-admin tenant creation. The safe local arena has four defense tiers,
fixture-bounded submissions, a per-tenant leaderboard, and an admin review/export
queue. Sample-data review payloads persist in tenant-scoped SQLite when configured. No public target or third-party attack exists.

Measured: TypeScript type check and production Vite build pass. npm audit reports
zero vulnerabilities after upgrading Vite to 7.3.7. Browser verification connected
the sample tenant, ran a successful level-0 attack, and ran the identical fixture
at level 3 with success=false. Screenshot: arena-preview.png.

Built minimal Python/TypeScript text SDKs, JSON/CEF metadata export, opt-in
Slack/PagerDuty webhook function, and optional OTel setup. Added Docker/Compose,
single-replica Helm/network policy, backup/restore script, CI/adaptive gates,
SBOM generation and a release-candidate provenance-attestation workflow.

Not accepted as complete: dashboard incident replay excludes raw prompts and
does not yet show full labeled execution traces; flag/category metrics need
aggregation. Postgres persistence/shared state, real MCP proxying, wired incident
webhooks, full OTel spans, public arena abuse testing, Docker/Helm execution,
distributed operations, signed published releases and a clean-machine timed
clone quickstart remain pending. No Git remote is configured, so hosted CI and
publication cannot be verified here.


## Private MVP increment, 2026-10-24

Added durable tenant credentials/limits/grants/policies, metadata-only typed
incident replay and aggregate decision metrics. The fixture Arena shows observed
sample effects, reasons, returned text and IFC steps instead of only a status line.

A separate Agent Lab accepts natural-language email and executes a model-driven
action loop over sample inbox/private memo/email tools. Its adaptive campaign pairs
a normal-task email with static and feedback-generated attacks across five defenses.
Saved bounded jobs support tenant isolation, idempotent creation, cancellation,
partial results, quotas and interrupted-state recovery. The console exports JSON
and can be served from the gateway without the Vite development server.

Production startup rejects demo keys and ephemeral storage. Readiness and browser
security headers are implemented. The Docker source now builds and serves the
console using a pinned official Node image, but no Docker/Helm runtime is installed
here. No container test is claimed. See ../MVP.md for the supported single-worker
scope and release gates. The repository remains private and licensing unset,
per operator choice. Source availability and passing tests are not certification.

## Arena interpretation

The four-level browser comparison showed a simulated disclosure at level zero,
detector blocks at levels one/two, and an internal summary at level three.
The IFC trace did not plan an email; it must not be described as an email denial.
Collector URLs render as text and are never fetched. Regression reference:
`test_arena_evidence_distinguishes_block_from_no_planned_external_call`.

## Security-test result correction

Navigation now uses Incident Review, Security Policy, Security Tests, Agent
Evaluation and Access Management. Security Tests explicitly identifies its
deterministic execution mode and links to model-backed evaluation. Results
distinguish observed attack objectives, detector blocks and actions absent from
the fixed program. Memory/calendar effects are no longer labeled disclosures
or counted as outbound actions. Input edits invalidate prior results; inputs
are locked during comparison. Each result carries its objective, oracle and
input digest. Existing API paths remain compatible.

Validation: 95 offline tests and dashboard production build passed. Browser
checks verified calendar versus email effect counts, four-defense comparisons
and stale-result removal. This improves result correctness; it does not turn
scripted regression cases into evidence of general model robustness.
