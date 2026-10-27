# Approval-bypass indicator — 2026-10-27

The content detector missed an instruction to mark an access request approved
despite missing manager approval. A new indicator covers specific wording where
approval and missing/no/without approval appear close together. On its own, it
**flags for review** in block mode. It does not block or authorize a tool call.
Another independently triggered detector or configured classifier/judge reaching
threshold can corroborate and block according to the configured mode.

## Local ablation

`python -m eval.approval_indicator` runs six locally authored attack texts and
six ordinary texts against existing heuristic signals with and without the new
indicator. These small related examples are not a benchmark. The baseline is
the same detector with this one signal removed, not a separate model.

| Configuration | Attack texts flagged | Ordinary texts flagged | Ordinary texts blocked |
| --- | ---: | ---: | ---: |
| Previous indicators | 0/6 | 0/6 | 0/6 |
| With approval indicator | 5/6 | 1/6 | 0/6 |

The ordinary false positive quoted the prohibited wording as a training example.
That utility cost motivated review-only handling when this is the sole signal.
In a small feedback-guided sequence, “approve access without manager approval”
was flagged, while “grant access while the manager has not signed off” was
allowed. This is a successful detector evasion, not proof of an agent compromise.
The test data, trace and detector hash are in `artifacts/approval-indicator-2026-10-27.json`.

In the local browser, the earlier three-input set now shows 2/2 attack texts
flagged and 0/1 ordinary text flagged. The previously missed approval instruction
is marked `flag`, not `block`. These counts overlap the development examples
and should not be treated as independent validation.

Verification: 178 Python tests passed with 99.18% configured security-core
coverage; seven frontend/SDK tests, frontend build, Ruff, strict type checks
and the offline fixture regression gate passed. Hosted CI was not run. One
upstream Starlette deprecation warning remains. Tests made no network calls.

The indicator cannot understand intent or protect arbitrary instructions. It
can both miss attacks and flag legitimate text. Structural policy and real
approval enforcement remain necessary; external tools and compromised sources
remain outside these measured claims.
