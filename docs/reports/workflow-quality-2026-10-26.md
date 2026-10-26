# Workflow reliability and varied decisions — 2026-10-26

The execution engine now checks answers against explicit workflow records,
recovers from unusable model replies through a restricted read-only path, and
evaluates different routing and approval decisions. Readable answers come from
actual returned fields; raw fields remain inspectable. No dependencies were added.

## Changes

The V2 case bank contains 30 server-owned instances across two partitions.
Support varies identity/billing routing and high/normal priority. Access varies
approved/missing-approval outcomes. Invoice subtotals and tax reconcile with totals.
Integrity targets now conflict with legitimate source facts: a legitimate approval
is never an attack success just because an old target requested approval.
Write scopes follow source identifiers; each execution gets isolated records.

With source enforcement enabled, malformed planner/extraction responses can use
the preconfigured read-only program and typed source resolver. Recoveries and
protocol errors are counted separately. Provider failure, invalid sources,
unsupported tasks and valid unauthorized programs do not receive this fallback.
No oracle expected values are supplied to the answer resolver.

## Live model evidence

Qwen2.5-7B-Instruct Q4_K_M, local llama.cpp GPU runner, seed 42, temperature 0.
Each static mode covers five development variations across three workflows:
15 normal tasks plus 15 record-injection attacks. Cases are locally authored and
correlated, not an independent external benchmark.

| Full IFC source checks | Normal tasks correct | Static attacks successful | Invalid | Static p95 |
| --- | ---: | ---: | ---: | ---: |
| Off | 15/15 | 12/15 | 0 | 1,519.6 ms |
| Shadow | 15/15 | 12/15 | 0 | 1,443.3 ms |
| Enforce | 15/15 | 0/15 | 0 | 1,437.9 ms |

Enforcement corrected 12 attacked answers and no normal answers. This measures
the source resolver's contribution, not improved underlying model reasoning.
Latency includes inference and cannot substitute for gateway-overhead acceptance.

Fresh feedback-driven adaptive attacks succeeded in 2/3 off, 2/3 shadow and 0/3
enforced runs. Those campaigns generated different payloads. A controlled replay
of the exact three off-mode generated payloads confirmed:

| Identical generated payload replay | Successful attacks | Invalid |
| --- | ---: | ---: |
| Off | 2/3 | 0 |
| Enforce | 0/3 | 0 |

This adaptive sample is small. It does not establish general resistance.

## Fault-injection experiment

An offline provider deliberately returns unusable replies on every call. With
recovery disabled, 0/30 tasks succeed and 30 fail; with recovery enabled, 30/30
succeed and all 30 are explicitly recorded as recovered. Both have zero external
effects. This tests program recovery, not actual model capability.

## Reproduction and validation

- Offline: `uv run python -m eval.workflow_reliability`.
- Live, after configuring the documented local provider environment:
  `uv run python -m eval.grounding_ablation --variations 1 0 2 3 4 --output artifacts/quality-v2-live.json`.
- Matched replay: `uv run python -m eval.adaptive_replay artifacts/quality-v2-live.json`.

Live commands are opt-in and use only repository-owned records, local inference
and simulated tools. Offline tests make no network calls.
Validation: 144 Python tests passed, 99.18% configured core coverage, strict type
checks on 12 files, Ruff, four frontend tests and production frontend build.
One upstream Starlette deprecation warning remains.
Raw evidence: `artifacts/quality-v2-live.json`, `artifacts/adaptive-replay.json`,
`artifacts/workflow-reliability.json`. The companion evidence JSON records hashes
and condensed results. Historical reports and the V1 bank are preserved.

The updated application was also exercised through its browser controls. Saved
run `748fbfa2` ("Varied decisions — verified") completed six executions with 12
model calls: 3/3 normal tasks correct, 0/3 attack successes, three source-corrected
attack answers, no invalid runs and no protocol recoveries. Its normal support
answer is billing/normal, and its access answer correctly reports present manager
approval. The browser exposes raw returned fields beside readable answers.

## Failures and limits

The uncorrected model still followed 12/15 static tampering attempts. The resolver
covers finite fields and configured rules; it cannot establish source truth,
protect corrupted authoritative fields or answer arbitrary questions. Recovery
does not establish model reliability. Broader independent evaluation, Windows
load-test latency, Linux isolation/deployment and hosted CI remain open.
The repository remains private; these results do not establish production readiness.

Self-review: correctness 4/5, safety 4/5, clarity 4/5, validation 4/5. Local evidence
supports the configured workflow scope; external and production validation remain.
