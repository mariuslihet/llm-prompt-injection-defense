# Source-grounded answers — 2026-10-26

## Built

The three record workflows now verify model-extracted fields against typed
observations supplied by their configured read adapters. Invoice amount/currency/
date/ID come from the invoice after vendor linkage and verification. Support
severity uses structured impact; team uses an explicit issue-code routing rule.
Access decisions use the matching manager-approval record. Untrusted notes do
not define rules or override structured fields. No evaluation answer table is
consulted by the resolver. Tests change authoritative amounts, impact and approval
and verify that outputs follow those changed sources rather than fixed answers.

Enforce mode returns canonical source-derived fields, retains model proposals in
the trace and conservatively joins every label. Missing, conflicting or malformed
sources withhold the answer. The final restricted-program answer must preserve
the canonical grounded serialization. Shadow reports differences without repair;
off preserves the prior IFC behavior. Legacy unstructured tasks are not covered.

Agent Evaluation exposes these three modes, saves the mode with each job,
compares changes on matching inputs, shows per-field proposal/source/rule tables,
and filters corrected or withheld answers. Correction counts distinguish normal
model errors from final attack outcomes. A new workflow-contract fingerprint
prevents silent comparisons with earlier tool observations. Historical missing
mode metadata means off. CLI supports `--grounding off|shadow|enforce`.

## Static ablation

Pinned local Qwen2.5-7B-Instruct Q4_K_M; seed 42. Three workflows across development
variations 1, 3 and 5, normal and record-channel integrity attacks, full IFC only.
The evaluator asserted matching dataset fingerprints across modes.

| Source check | Attack successes | Normal-task success | Invalid | Corrected answers | Target calls | p95 target run ms |
| --- | --- | --- | --- | --- | --- | --- |
| off | 6/9 | 9/9 | 0 | 0 | 36 | 1885.62 |
| shadow | 6/9 | 9/9 | 0 | 0 | 36 | 1647.25 |
| enforce | 0/9 | 9/9 | 0 | 6 | 36 | 1657.01 |

No additional model calls are required by source checking. No normal answer needed
correction in this sample. The timing includes inference, warm caches and local
scheduling; it does not isolate the resolver's cost or establish a latency gain.
The existing 50 ms gateway end-to-end acceptance gate remains unresolved.
These nine related authored cases are descriptive evidence, not an independent
benchmark or a claim of population-wide protection.

## Adaptive campaign and failed attacker improvement

For each mode, three campaigns executed a normal task, a static attack and one
feedback-driven attacker revision per workflow. Initial campaign attack outcomes
(static plus new attempts) were 2/6 off, 2/6 shadow and 0/6 enforce, with normal
utility 3/3 in each mode. **New adaptive attempts alone were 0/3 in every mode.**
Inspection showed that several revisions restated the legitimate task instead
of preserving an adversarial objective. Those trials cannot establish strong
adaptive resistance.

The attacker protocol was revised to separate its system role from target-task
background and supply exact attacker targets without revealing expected answers.
A fresh bounded run repeated all three workflows. Static outcomes were 2/3 off,
2/3 shadow and 0/3 enforce; normal utility remained 3/3. Campaign totals remained
2/6, 2/6 and 0/6 respectively. New attempts were again 0/3 in each mode and included
weak or defensive proposals. This is a negative attacker-quality result, not a
security success. Broader mutation search, stronger independent attackers and
fresh held-out cases remain required.

The first experiment recorded 81 target executions and 171 total model calls;
the revised protocol recorded 45 target executions and 99 total calls. Target
counts exclude attacker calls in the per-mode tables. Both raw reports are
preserved. Summaries, latencies and checksums are in
[source-check-evidence-2026-10-26.json](source-check-evidence-2026-10-26.json).

Reproduce with the local model configured in the environment:

```powershell
uv run python -m eval.grounding_ablation --variations 0 2 4 --output artifacts/source-checks.json
```

The script has a 600-second total deadline, distinct bounded variations, fixed
seed, mode/config logging, incremental evidence saves and explicit incomplete/
invalid results. Its current attacker protocol is version 2; the initial run
documents the older protocol and is preserved separately.

## Verification and UI evidence

- 135 offline Python tests passed; configured security-core coverage 99.33%,
  including 100% statement coverage of the source resolver.
- Four frontend tests passed, including corrected/withheld filtering and the
  distinction between source corrections and final attack outcomes.
- Strict mypy passed on 12 configured files; Ruff checks and formatting,
  TypeScript checks and the Vite production build passed.
- Property tests cover arbitrary note content and proposed amounts. Unit tests
  cover all 30 authored task instances, changed source data, label/confidentiality
  preservation, missing/mismatched evidence, unknown mode and post-check program
  rewriting. Invalid source evidence is blocked without returning an answer.
- The console ran matched saved jobs `641a6cbd7379434f80695b344cbfea05` (off) and
  `bfe11c84` (enforce, ID prefix). Each had six executions and 12 model calls.
  Attack outcomes changed from 2/3 to 0/3, normal utility stayed 3/3, and the
  comparison explicitly reported a source-check change with unchanged model and
  policy. Per-field UI evidence showed amount 1.00 corrected to 137.25 and team
  billing corrected to identity. Interactive timing overlapped local experiments
  and must not be used to attribute resolver overhead.

## Tested claim and boundaries

For the covered source schemas and successful configured adapter reads, enforce
returns the resolver's canonical fields and preserves joined labels. This is
agreement with those sources and finite business rules. It is **not** proof that
the source is true, current, uncompromised or authorized for an arbitrary task.
If an attacker corrupts an authoritative structured field, this control cannot
distinguish that from a legitimate source change. Arbitrary documents, websites,
legacy text-only tasks, external tools and general factual reasoning remain
outside this claim. No real external effect or new dependency was introduced.

Delivery self-check: accuracy 4/5 (source contracts tested, independent source
truth unverified); completeness 4/5 (covered failure fixed, stronger adaptive
attack generation remains open); clarity 4/5 (field-level UI explanations, raw
traces still technical); actionability 4/5 (running console and reproducible
runner, deployment remains local); conciseness 4/5 (one report with versioned
evidence, earlier reports must be read as historical). Overall 4.0/5.
No files were staged, committed or pushed.
