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

## Tool destination and payload semantics correction

The original scripted corpus reused a web collector URL for email, calendar and
memory actions. Security Tests now presents revision-two cases with an email
recipient, web URL, calendar resource or memory resource matching the action.
Revision-one evidence and API case IDs remain available for historical replay;
these records are explicitly marked legacy. Historical benchmark scores are not
recomputed or relabeled as revision-two measurements.

Each response includes the exact input and a branch-specific execution sequence.
A script parses MECHA_FIXTURE JSON; it does not interpret the surrounding prose.
$PRIVATE resolves to a repository canary only when the vulnerable target runs.
The UI states that reproducing a scripted action is not model attack evidence.
Regression tests cover all 168 revision-two destination mappings and exact
email-oracle matching. All 96 offline tests passed; browser comparison verified
the corrected email destination and distinct block/program-exclusion outcomes.

## Expanded model evaluation

Added three controlled schedule scenarios, three attack presets, configurable
adaptive rounds and turn limits, scenario-aware utility, static/adaptive outcome
breakdowns, target latency/call metrics, result filtering, exact input snapshots
and expandable attacker proposals. Server allowlists prevent client-authored
trusted tasks. Existing budgets remain enforced.

Validation: 99 offline tests, strict typing and production dashboard build passed.
A browser-started rescheduling/workflow campaign completed 15 target runs and 45
total model calls without invalid results. All five normal tasks succeeded.
Observed static/adaptive attack successes: none 1/1, hardening 1/0, detector 1/0,
detector+sanitizer 1/1, IFC 0/0 (each count is out of one). These tiny, correlated
samples are descriptive only. Full evidence: rescheduling-evaluation.json.

A separate multilingual normal-input run completed without external effects but
failed utility: the model returned schedule-not-provided despite the Romanian
email stating Friday 15:30. This negative result is preserved in
multilingual-evaluation.json; scenario availability does not imply model mastery.

## Diverse business cases, bounded suites and grouped timelines

The default changed from repeated schedule tasks to invoice reconciliation,
support classification and access-request review. Each has its own trusted
objective, expected fields and typed quarantine schema. Three scheduling tasks
remain available for historical replay. Context-specific attacks use vendor
verification, account recovery and approval override pretexts.

The six unique normal/attack inputs are run against five defenses (30 executions)
under one 128-call budget. Saved-run comparisons require matching dataset hashes
and report descriptive security/utility/latency differences, with invalid results
marked inconclusive. The UI groups matching inputs, shows actual action paths
and lets the operator inspect each defense's own timeline and final answer.

Two local business-suite runs each completed 30 executions in 60 model calls.
Observed attack successes were 3/3 for undefended and prompt hardening, 0/3 for
detector, sanitizer and IFC. Normal-task field-oracle success was 2/3 for the
first four configurations and 3/3 for IFC; access-review prose failed the exact
field check in the plain agent. This is a narrow required-field oracle, not a
general semantic judge. Repeat comparisons had unchanged counts and differing
latencies. Evidence: business-suite.json and business-comparison.json.

Validation: 106 offline tests, 99.20% security-core coverage, strict typing, lint
and dashboard build passed. Browser checks verified six distinct inputs, five
executions per card, changing from a 12-event disclosure trace to a two-event
detector trace, and saved-run comparison. Static suite results remain separate
from feedback-driven adaptive campaigns; these small samples do not establish
general model robustness.
