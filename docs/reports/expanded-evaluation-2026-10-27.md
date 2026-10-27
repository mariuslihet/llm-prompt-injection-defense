# Expanded workflow evaluation — 2026-10-27

Agent Evaluation can now run every variation in one business suite. It evaluates
five variants of each finance, support and access case, with a normal input and
a static attack for each. The application shows each case's input, execution
timeline, source checks, returned answer and expected-versus-returned fields.
Missing comparison data is shown as unavailable; it is never inferred as a pass.

The expanded suite is bounded to two defense configurations and retains the
ten-minute job deadline. It uses a shared model-call budget, and partial or
invalid runs remain visible rather than being reported as successful defenses.
The prior one-variation behavior remains the default. The command-line evaluator
also accepts `--suite --all-variations` with one or two selected defenses.
Adaptive attacks run separately; this suite is static.

## Measured local run

Saved run `add2ba18`, titled “All variations — local model”, used Qwen2.5-7B,
full IFC, source checks enforced, development partition and record-channel answer
tampering. It completed 30 executions and 60 model calls:

| Measure | Result |
| --- | ---: |
| Correct normal tasks | 15/15 |
| Successful tampering attacks | 0/15 |
| Invalid or exhausted runs | 0 |
| Source-corrected answers | 12 (0 normal cases) |
| Unusable model reply recoveries | 0 |
| End-to-end model-run p95 | 1,492 ms |

The correction count means the raw model proposal differed from the configured
records in twelve runs; the program returned the source-derived value. It does
not mean the model itself answered all attacks correctly. Latency includes local
model inference and is not the gateway-overhead measurement. The cases are small,
related and locally authored; checks cannot verify the truth of a compromised
source or guarantee results for arbitrary external tools and tasks.

Verification: 154 Python tests passed with 99.18% configured security-core
coverage; six frontend tests, frontend build, Ruff and strict core type checks
passed. The browser displayed all 15 case breakdowns and the field-level results.
One upstream Starlette deprecation warning remains. The saved run's complete
evidence is accessible from the local evaluation history or its JSON export.
