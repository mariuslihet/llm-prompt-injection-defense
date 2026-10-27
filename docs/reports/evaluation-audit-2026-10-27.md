# Evaluation reliability audit — 2026-10-27

## Findings and changes

1. **Misleading adaptive comparisons.** A matching configuration did not prove
   generated payloads matched. Comparisons now require the same recorded payload
   hashes, case IDs and rounds for each defense. Missing evidence is rejected.
   The dataset fingerprint also includes scenario-building and scoring code.
2. **Repeated attacks.** A generated proposal that repeats the normal input or
   an earlier input for that defense is rejected and the affected defense is
   marked inconclusive. A normal input cannot be submitted as a campaign attack.
   A failed proposal no longer marks unrelated defenses inconclusive. A run with
   no attacks cannot establish attack resistance.
3. **Wrong source manifest.** The model report recorded the V1 case bank while
   using V2. It now hashes the actual case bank and source-check implementation.
4. **Unclear failures.** The UI explains provider failures, exhausted budgets and
   withheld source checks. API validation errors are shown as readable messages
   rather than JavaScript object text. Provider exception contents are not exposed.
   Missing comparison latency displays as unavailable instead of crashing the page.
   The comparison shows changes to recovery as well as model, policy and checks.
5. **Corpus repetition.** The existing 168 fixture entries include 101 distinct
   payload strings. Reports now include corpus diversity counts, and the historical
   corpus and its prior reports remain unchanged. Fixture categories and channels
   do not make repeated payloads independent tests.

## Local verification

All 153 Python tests passed with 99.18% configured security-core coverage; Ruff,
formatting, strict type checks, five frontend tests and the frontend build passed.
The offline
fixture benchmark and its regression gate passed. The browser rejected a normal
input submitted as an attack with an explanatory message. New regression cases
exercise changed adaptive payloads, missing evidence and latency, repeated
proposals, per-defense failure isolation, missing attack evidence, provider
failures and report provenance.

The Qwen2.5-7B local model was re-evaluated against development variation 2 of
the three workflow scenarios. In each setting, 3/3 normal tasks were correct.
Static tampering succeeded 3/3 with source checks off, 3/3 in shadow mode and
0/3 with checks enforced. Fresh adaptive proposals succeeded 2/3 off, 2/3 in
shadow mode and 0/3 enforced; the generated proposals can differ by setting.
All target executions completed without invalid runs. These samples are small,
correlated and limited to repository-owned records and simulated tools.
The generated input may be valid text without being a meaningful attack; syntax
and non-repetition checks do not establish attack quality. The raw run, including
its exact source hashes, is `artifacts/audit-live-2026-10-27.json`.

## Remaining limitations

The fixture corpus still has repeated templates and is not a measure of real-world
robustness. The record suite contains locally authored related cases, and its
held-out partition was inspected during development. The program cannot guarantee
correct answers for arbitrary tasks or compromised source records. Linux runtime
isolation, production deployment, hosted CI and the Windows latency gate remain
unverified or failed as recorded in `docs/LIMITATIONS.md`. This audit does not
establish that every possible failure is fixed or that the platform is flawless.

Self-review: accuracy 4/5 (supported by local evidence; small live samples),
completeness 3/5 (independent diverse benchmarks and production validation remain),
clarity 4/5 (errors and evidence are explicit), actionability 4/5 (changes and
remaining gaps are recorded), conciseness 4/5 (details are retained for audit).
Overall 3.8/5. Highest-impact next work: author independent, genuinely varied
cases and test them against multiple models; validate deployment and latency in
the intended environment. A user seeking flawless behavior would reasonably
consider those unverified areas incomplete.
