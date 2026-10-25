# Acceptance register

Status vocabulary: verified = locally tested for the documented simulated scope;
partial = some implementation/evidence; pending = not implemented or not run.
No phase is certified against all mission acceptance criteria yet.

| Phase | Requirement | Status and evidence |
| --- | --- | --- |
| 0 | Plan, threat model and three trifecta targets | Verified for synthetic sample-data scope |
| 0 | 150+ versioned attacks with deterministic oracles | Verified: 168 JSONL records, 21 categories |
| 0 | Baseline and end-to-end exfiltration | Verified: 504/504 effects, mecha demo-attack |
| 0 | CI acceptance | Pending hosted CI; local offline tests pass |
| 1 | Drop-in multi-provider gateway / streaming | Partial: strict text subset, buffered SSE, opt-in provider clients |
| 1 | Tenant keys, RBAC, limits, hooks | Verified locally with persistent SQLite keys, limits and single-use grants |
| 1 | Labeling and spotlighting | Verified; delimiter wrapper is not the structural boundary |
| 1 | Heuristics + classifier + optional judge | Partial: trained/calibrated local BERT artifact and held-out fixture results; broad real-agent calibration pending |
| 1 | Egress/secret/PII/Unicode sanitation | Partial: conservative text/URL/canary/email controls, not comprehensive PII detection |
| 1 | Chained audit / traces | Verified local typed label/decision replay and optional Ed25519 external anchor; external retention is an operator responsibility |
| 1 | p95 <50ms and 300+ normal-task tasks | Partial: in-process p95 27.37 ms and localhost concurrency 4 p95 18.23 ms; concurrency 16 p95 374.47 ms FAILED; 336 template tasks |
| 2 | Labeled propagation / quarantine / restricted interpreter | Verified finite linear DSL and deterministic extractor |
| 2 | Real planner/quarantined LLMs | Partial: opt-in planner/quarantine provider boundaries and model-driven email runner; representative quality evidence pending |
| 2 | Policy per argument, approval, shadow, revisions | Verified durable local revisions and approvals; distributed rollout pending |
| 2 | Static data-flow verifier | Verified finite source/transform/sink graph and preflight; arbitrary Python/tool internals not covered |
| 2 | Taint fallback | Verified conservative session fallback |
| 2 | Claims, property tests, ~0 covered ASR | Verified within finite simulated scope; see SECURITY_CLAIMS and latest.json |
| 3 | Static/adaptive ASR, utility, FPR, latency, cost, reports | Verified fixtures; real token/cost measurement pending |
| 3 | Confidence intervals and seeds/config hashes | Verified descriptive Wilson intervals; correlated-trial limitation documented |
| 3 | AgentDojo/InjecAgent/BIPIA/garak/promptfoo | Partial local-export adapters; upstream executions pending |
| 3 | Mutations and feedback search | Verified seeded black-box campaign; LLM proposer adapter not run |
| 3 | Evolutionary and policy-aware real attacker campaigns | Partial: seeded evolutionary and policy-aware fixture campaigns run; natural-language model-attacker campaign implemented |
| 3 | PR/nightly gates | Implemented workflows; hosted CI unrun |
| 3 | Per-layer ablations | Partial ordered five-configuration comparison; full factorial per-component study pending |
| 4 | Self-play | Measured NB overfitting and two BERT feedback-retraining rounds; false positives worsened without evasion benefit |
| 4 | Activation probes / DPO | Measured bounded local DPO: no preference gain; behavior probe not trainable (invalid action responses) |
| 4 | MCP security | Verified catalog pins, Ed25519 signatures and bounded opt-in HTTP transport with mocked interoperability; live servers unverified |
| 4 | Multimodal/exotic | Measured HTML, invisible PDF text and PNG metadata fixtures; OCR and visual-model evaluation pending |
| 4 | Memory/multi-agent / deception | Verified label/quarantine/honeytool components; live multi-agent evaluations pending |
| 4 | gVisor/Firecracker/default-deny egress | Partial bounded gVisor runner and DNS-pinned default-deny HTTPS transport; live isolation/forwarding unverified, Firecracker absent |
| 5 | Dashboard and arena | Verified local build/browser smoke, typed replay, aggregate metrics, detailed arena and durable Agent Lab jobs; public arena pending |
| 5 | SDKs/integrations | Partial text SDKs and integration functions; interoperability/delivery not certified |
| 5 | Docker/Helm/self-host/backup/upgrade | Assets/docs present; deployment runtime verification pending |
| 5 | Open-source release/publication/disclosure | Explicitly deferred: operator chose private repository and local verification; license remains unset |
| 5 | Clone-to-protected-demo under10min | Local commands/build checked; clean-machine timing not verified |

## Project definition of done

1. All phase acceptance criteria and green hosted CI: **not met**.
2. Published benchmark including real adaptive attacks and ablations: **not met**;
   local synthetic report exists.
3. Claims only from tests and honest limitations: **met for current prototype**.
4. Clean-machine quickstart: **not yet verified**.
5. Final report and roadmap: current handoff report exists; research program remains open.

## Private MVP gate

See [MVP runbook](MVP.md) and [current report](reports/FINAL.md). Single-worker
email-agent execution, adaptive natural-language campaigns and bounded durable
jobs are implemented. Production acceptance remains open until valid model
evaluation, durable network latency, Linux deployment and independent security
review are evidenced. User-approved model acquisition is local inference only.


## Workflow increment — 2026-10-25

Distinct scoped record tools, 30 versioned task instances, integrity/memory outcomes,
operator approval review and restore rehearsal are implemented and locally tested.
117 offline tests pass. Live integrity attacks still altered 2/3 IFC answers;
concurrency-16 end-to-end p95 was 348.90 ms, above the 50 ms gate.
See [the measured workflow report](reports/workflow-improvements-2026-10-25.md).
Production acceptance remains open; no publication or Git mutations were performed.
