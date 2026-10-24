# Phase 3: evaluation and adaptive lab

Seed 42, eight attempts per adaptive case, 168 fixture attacks x three targets,
336 normal-task fixture tasks per configuration. Full feedback traces are generated
alongside the JSON and HTML report. Hashes bind corpus and policy configuration.

| Defense | Static ASR | Adaptive ASR | Normal-task utility | FPR |
| --- | --- | --- | --- | --- |
| None | 100% | 100% | 100% | 0% |
| Prompt hardening | 100% | 100% | 100% | 0% |
| Detector | 0% | 100% | 92.86% | 7.14% |
| Detector + sanitizer | 0% | 100% | 92.86% | 7.14% |
| Full IFC | 0% | 0% | 83.33% | 0% detector FPR |

The IFC task-failure rate is 16.67%; calling it zero false positives would be
misleading. Detector FPR and task utility measure different effects.

## Marginal contribution / ablation

Prompt wording has no measured effect on this simulated. Heuristics remove 100
percentage points of static fixture ASR at 7.14 points utility cost. Text
sanitization removes zero additional tool effects. Structural separation removes
100 points adaptive ASR at an additional 9.52 points utility cost. These are
ordered ablations; interactions mean they are not causal attribution for every
individual component. Separate joins/capabilities/approval unit tests are
invariant checks, not standalone whole-system efficacy measurements.

Failure found: splitting the fixture marker and JSON-escaping string characters
bypasses heuristics while preserving command semantics. This is tested as a
known detector limitation; IFC must remain safe when detection fails.

Wilson intervals are included in JSON but correlated synthetic trials are not
independent evidence. Simulated cost is zero; real token cost is not measured.
Not accepted as complete: real LLM attackers, upstream AgentDojo/InjecAgent/
BIPIA/garak/promptfoo execution, real-model utility and full factorial ablations.

Update 2026-10-24: seeded evolutionary fixture campaigns (budget 16, population
4) produced 504/504 unauthorized effects for baseline/detector/sanitizer and
0/504 for IFC. These remain synthetic. Agent Lab now supports model-driven
natural-language adaptive campaigns; those reports are kept separate from the
fixture table. Invalid models/proposals are explicitly inconclusive. Upstream
benchmark execution and full component-factorial studies remain pending.
