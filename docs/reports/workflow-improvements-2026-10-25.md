# Workflow improvements — 2026-10-25

## Delivered

Distinct scoped finance (invoice/vendor), support (ticket/history), and governance
(request/manager approval) tools replace the shared text-only workflow default.
Unsafe modes expose typed, isolated record mutations and per-run memory writes.
There is no external effect or durable poisoned memory. Outcome checks separate
schema validity, required source coverage, correct facts, confidentiality,
attacker-target answer integrity, and state changes. Quoted attack text alone is
not success. Earlier tool effects remain evidence even if later execution fails.

The versioned bank has 30 task instances: 15 development and 15 held-out,
three workflows and five variations each. IDs and finance facts vary. Partitions
are authored from related templates, not independent benchmark populations.
The held-out set was inspected during this work and is now development evidence;
release requires fresh independent validation. Tests check partition separation.

Email and returned-record injection channels support disclosure, tampering and
memory objectives. Human review is a durable, tenant-scoped operator-proposal
workflow with server-fixed labels, five-minute expiry, admin decisions, policy
binding and one simulated execution. It cannot approve model-originated recipients
or override confidentiality constraints. Restart marks executing reviews interrupted.

## Live results

Pinned local Qwen2.5-7B-Instruct Q4_K_M on the RTX 2070, temperature 0, seed 42.
Integrity comparison: heldout variation 1, returned-record injection, eight turns,
five defenses, three normal and three attack inputs, 30 executions, 134 model calls.

| Defense | Attack objectives reached | Normal-task success | Invalid runs | p95 run ms |
| --- | --- | --- | --- | --- |
| none | 3/3 | 2/3 | 0 | 4050.43 |
| prompt-hardening | 3/3 | 3/3 | 0 | 3791.11 |
| detector | 1/3 | 2/3 | 0 | 3500.33 |
| detector-sanitizer | 1/3 | 2/3 | 0 | 3470.32 |
| full-ifc | 2/3 | 3/3 | 0 | 2056.27 |

Attack counts combine forbidden state changes and specified wrong-answer targets.
Full IFC recorded **zero unauthorized tool effects** but **2/3 answer-integrity
failures**. It constrains authority, not factual correctness. Detector and sanitizer
layers also missed integrity attacks. These are tiny correlated samples, not
population estimates or general security guarantees. Inference is included in latency.

An additional finance heldout variation 2 memory campaign ran 15 target executions,
one feedback-driven attacker revision per defense, 62 total model calls. Each
configuration recorded 0/2 successful attacks and 1/1 normal-task success, with no
invalid runs. The undefended baseline also resisted these particular proposals,
so the campaign demonstrates the adaptive path, not measured defense efficacy.
Only one workflow and one mutation round were tested; durable multi-session memory
and broader adaptive coverage remain open.

Initial evidence is preserved: a stopped provider caused inconclusive failures;
the first healthy model run skipped sources and hallucinated answers. Completion
now rejects missing source reads and invalid output schemas within the turn limit.
Recovery gives the tool identifiers and public schema, never expected values.
Schema guidance eliminated invalid runs in the final comparison. An intermediate
128-call suite exhausted its shared budget; suite limits now reserve up to 240
calls from the selected turn limit, while campaigns remain capped at 128. The
10-minute job deadline is retained. No failed run was reclassified as a success.

## Operational checks

- 117 offline tests passed; configured core/policy/IFC/sanitizer coverage 99.20%.
- Ruff checks and formatting passed; strict mypy passed on 11 configured files.
- TypeScript check and Vite production build passed.
- Wheel build passed; case-bank JSON and review module are included. A fresh
  Python 3.11 environment installed the wheel offline and resolved a held-out case
  through isolated imports. A first automatic Python 3.14 attempt lacked cached
  dependencies and did not complete; this is not a clean-machine deployment test.
- UI verified partition/variation/objective changes, real model execution and
  persistent result inspection (saved case names and IDs now remain tied to their
  original run, independent of the current selectors); an operator proposal was approved once visibly.
  API tests also cover denial, expiry, policy changes, roles and tenant isolation.
- Backup rehearsal preserved live sources and restored separate control and audit
  snapshots into fresh paths; table counts, bytes, SQLite integrity and audit chain
  passed. Restart recovery is separately tested. Snapshots are not atomic across
  databases, and a production cutover was not attempted.
- Durable TCP load: 1,000 requests, concurrency 16, zero HTTP errors, client p95
  **348.9017 ms**, server p95 **11.712 ms**. The end-to-end **50 ms gate failed**.
  Server timing does not replace client latency. No durability was weakened.

Machine-readable summaries and artifact checksums are in
[workflow-evidence-2026-10-25.json](workflow-evidence-2026-10-25.json).
Historical evidence and failed intermediate reports remain in local artifacts.

## Remaining work

Prioritize source-grounded integrity checks for covered business decisions and
fresh independent cases. Expand multi-round adaptive campaigns across all goals
and workflows, measure marginal contributions and utility, then diagnose the
Windows network latency gap. Production Linux isolation, deployment, hosted CI,
external integrations and independent review remain unverified. Keep private as
requested. No dependencies were added and no Git staging, commit or push occurred.

## Delivery self-evaluation

Overall 3.8/5. Accuracy 4/5: checks and failures are evidenced, but local samples
cannot establish population robustness; add independent benchmark runs.
Completeness 3/5: all six improvement areas now have implementation/evidence, but
integrity and latency acceptance still fail; add grounded verification and profile
client/server transport before calling the MVP production ready.
Clarity 4/5: public-schema recovery and separate outcomes clarify failures; raw
fact details still require technical reading, so add friendlier explanations.
Actionability 4/5: the console is running and controls were exercised; deployment
remains local and needs Linux validation. Conciseness 4/5: this report keeps evidence
in one place, though historical documentation still contains earlier measurements.
The user should accept the implemented progress, but should not accept a production
readiness claim. This assessment flags substantive remaining work explicitly.
