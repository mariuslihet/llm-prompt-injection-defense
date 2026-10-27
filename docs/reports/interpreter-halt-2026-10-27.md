# Stop restricted execution after denial — 2026-10-27

The interpreter previously denied an individual tool call but continued the
remaining program. It now stops the current invocation after the first denied
call. The trace records the denied decision, halt position and skipped count.
Instructions before the denial may already have recorded effects; they are not
undone. Later approval grants are not consumed. Both enforce and shadow modes
use this rule.

Security Tests includes two fixed multi-step examples: deny first, and summarize
before denial. In the second example the local app showed three planned steps,
two processed (one allowed and one denied), one skipped and one earlier simulated action. No email was sent.
The audit trace includes decision metadata, not the sample document.

Property-based tests vary the number of earlier/later calls and both policy
modes. Additional tests cover preserved earlier effects, unconsumed later approval,
historical trace compatibility, the API and authorization. These support the
specific C8 claim in `SECURITY_CLAIMS.md`; they do not prove safety of external
tools or malicious trusted adapters.

An offline fixture comparison with the immediately preceding run showed the same
static and adaptive totals: full IFC had 0/504 fixture attack successes and
280/336 normal-task successes both before and after. This unchanged 56/336 utility
cost remains significant. The fixture evaluator uses simple correlated templates;
it does not measure general agent behavior or the utility cost of stopping
multi-step real workflows. The offline regression gate passed.

Local verification: 188 Python tests passed, configured security-core coverage
99.19%, seven frontend/SDK tests, frontend build, Ruff and strict core type checks
passed. The tests make no network calls. Hosted CI and production isolation were
not run; one upstream Starlette deprecation warning remains. Reproduction:
`python -m pytest tests/test_ifc_halt.py` and the offline fixture benchmark with
seed 42 and budget 8. Evidence is in `artifacts/halt-ci-2026-10-27.json`.
