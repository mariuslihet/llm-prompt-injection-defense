# Acceptance register

Status vocabulary: verified = locally tested for the documented mock scope;
partial = some implementation/evidence; pending = not implemented or not run.
No phase is certified against all mission acceptance criteria yet.

| Phase | Requirement | Status and evidence |
| --- | --- | --- |
| 0 | Plan, threat model and three trifecta targets | Verified for synthetic fake-data scope |
| 0 | 150+ versioned attacks with deterministic oracles | Verified: 168 JSONL records, 21 categories |
| 0 | Baseline and end-to-end exfiltration | Verified: 504/504 effects, mecha demo-attack |
| 0 | CI acceptance | Pending hosted CI; local offline tests pass |
| 1 | Drop-in multi-provider gateway / streaming | Partial: strict text subset, buffered SSE, opt-in provider clients |
| 1 | Tenant keys, RBAC, limits, hooks | Verified locally; process-local state only |
| 1 | Labeling and spotlighting | Verified; delimiter wrapper is not the structural boundary |
| 1 | Heuristics + classifier + optional judge | Partial: configurable cascade and local model adapter; no trained/calibrated artifact |
| 1 | Egress/secret/PII/Unicode sanitation | Partial: conservative text/URL/canary/email controls, not comprehensive PII detection |
| 1 | Chained audit / traces | Partial: SQLite metadata chain; no full execution replay or anchored chain |
| 1 | p95 <50ms and 300+ benign tasks | Verified in-process mock: load.json; 336 template tasks; deployment pending |
| 2 | Labeled propagation / quarantine / restricted interpreter | Verified finite linear DSL and deterministic extractor |
| 2 | Real planner/quarantined LLMs | Pending real-model integration/evaluation |
| 2 | Policy per argument, approval, shadow, revisions | Verified local APIs/tests; durable/distributed rollout pending |
| 2 | Static data-flow verifier | Partial: conservative finite AST paths; no general graph over arbitrary tools |
| 2 | Taint fallback | Verified conservative session fallback |
| 2 | Claims, property tests, ~0 covered ASR | Verified within finite mock scope; see SECURITY_CLAIMS and latest.json |
| 3 | Static/adaptive ASR, utility, FPR, latency, cost, reports | Verified fixtures; real token/cost measurement pending |
| 3 | Confidence intervals and seeds/config hashes | Verified descriptive Wilson intervals; correlated-trial limitation documented |
| 3 | AgentDojo/InjecAgent/BIPIA/garak/promptfoo | Partial local-export adapters; upstream executions pending |
| 3 | Mutations and feedback search | Verified seeded black-box campaign; LLM proposer adapter not run |
| 3 | Evolutionary and policy-aware real attacker campaigns | Pending; current search is a small feedback-guided mutation loop |
| 3 | PR/nightly gates | Implemented workflows; hosted CI unrun |
| 3 | Per-layer ablations | Partial ordered five-configuration comparison; full factorial per-component study pending |
| 4 | Self-play | Verified NB diagnostic failure; transformer loop pending |
| 4 | Activation probes / DPO | Scripts present; no run, no measured claim |
| 4 | MCP security | Verified local catalog tests; public-key signing/live transports pending |
| 4 | Multimodal/exotic | Partial HTML fixture; OCR/PDF/image experiments pending |
| 4 | Memory/multi-agent / deception | Verified label/quarantine/honeytool components; live multi-agent evaluations pending |
| 4 | gVisor/Firecracker/default-deny egress | Partial gVisor fail-closed runner; live isolation, Firecracker and forwarding proxy pending |
| 5 | Dashboard and arena | Verified local build and browser smoke; full replay/metrics/public arena pending |
| 5 | SDKs/integrations | Partial text SDKs and integration functions; interoperability/delivery not certified |
| 5 | Docker/Helm/self-host/backup/upgrade | Assets/docs present; deployment runtime verification pending |
| 5 | Open-source release/publication/disclosure | Pending remote, owner-approved license/contact, publication and signing |
| 5 | Clone-to-protected-demo under10min | Local commands work; remote absent and clean-machine timing not verified |

## Project definition of done

1. All phase acceptance criteria and green hosted CI: **not met**.
2. Published benchmark including real adaptive attacks and ablations: **not met**;
   local synthetic report exists.
3. Claims only from tests and honest limitations: **met for current prototype**.
4. Clean-machine quickstart: **not yet verified**.
5. Final report and roadmap: current handoff report exists; research program remains open.
