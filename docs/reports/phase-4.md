# Phase 4: research infrastructure and measured failures

## Completed local experiments

`uv run python -m training.selfplay --output docs/reports/selfplay.json` uses
seed 42, 14 training categories, seven held-out categories, and a held-out
JSON-escape operator. It is an inexpensive Naive Bayes baseline.

| Round | Training evasion rate | Held-out evasion rate | Benign FPR |
| --- | --- | --- | --- |
| 0 | 28.57% | 100% | 0% |
| 1 | 0% | 100% | 0% |
| 2 | 0% | 100% | 0% |
| 3 | 0% | 100% | 0% |

![Held-out self-play failure](selfplay.svg)

What we learned: improvement on feedback-selected training attacks did not
transfer to the held-out mutation. Reporting the training rate alone would
have hidden complete held-out failure. Benign fixtures remain simple templates.

MCP tests exercise pin changes, description poisoning, server permissions,
cross-server shadowing and HMAC integrity. Memory/sub-agent tests confirm that
neither clean detection nor a trusted sender promotes stored/sub-agent content.
HTML fixture tests observe two hidden elements and flag an override instruction;
honeytool access produces a high-severity decision. These are component tests,
not live MCP, browser, OCR or incident-notification experiments.

## Not run / not implemented

| Experiment | Implementation / result | Missing evidence |
| --- | --- | --- |
| HF classifier fine-tuning | Local-only script; not run | Local pretrained model, calibration/held-out results, ablation |
| HF activation probe | Linear-probe script; not run | Observed behavior labels, model activations, MLP/adaptive comparison |
| Hierarchy DPO | LoRA/TRL script; not run | Local causal model, training result and broad capability evaluation |
| Transformer self-play | Not implemented | Repeated measured retraining with frozen holdouts |
| Image/OCR and hidden PDF | Not implemented | Sandboxed extraction and measured multimodal experiments |
| gVisor | Fail-closed runner and command tests | Linux Docker/runsc runtime verification |
| Firecracker | Not implemented | Linux KVM/jailer integration and isolation evidence |
| Forwarding egress proxy | Decision primitive only | DNS-pinned transport, redirect validation and network tests |

The optional full dependency lock was audited without installing models; no
known vulnerabilities were reported by pip-audit at the time of the run.
No optional pretrained model, real API key or GPU was present. This phase is
**not accepted as complete**. Scripts are research starting points, not results.
