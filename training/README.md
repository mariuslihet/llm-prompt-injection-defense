# Research experiments

All inputs must be fake-data fixtures. No script enables tool execution from
model output. Heavy model research is optional; model assets must exist locally.

Run the measured inexpensive baseline:

```
uv run python -m training.selfplay --output artifacts/selfplay.json
uv run python -m training.data --output artifacts/training
```

The self-play script trains a simple multinomial Naive Bayes detector and adds
feedback-selected evasions. Whole categories and a JSON-escape mutation are
held out. The committed result shows complete held-out failure despite training
improvement. This is an overfitting demonstration, not the requested transformer
self-play experiment. It writes JSON and an SVG plot.

Optional transformer research:

```
uv sync --extra research
uv run python -m training.hf_experiments classifier --model PATH_TO_LOCAL_MODEL --data artifacts/training/classifier.jsonl --output artifacts/classifier-run
uv run python -m training.hf_experiments dpo --model PATH_TO_LOCAL_CAUSAL_MODEL --data artifacts/training/hierarchy.jsonl --output artifacts/dpo-run
```

Use a fresh output directory. Scripts never download weights, enable remote
code or execute generated code. Classifier training reports attack misses and
benign false positives before/after two epochs. DPO uses LoRA for one CPU epoch
and compares held-out security/general preference likelihoods. These preference
metrics do not measure tool-agent ASR or general capability comprehensively.

Probe inputs must include observed model-behavior labels for whether the model
followed an instruction from untrusted data. Do not reuse presence-of-injection
labels and call them behavior probes. Pass the observed fixture JSONL to the
`probe` subcommand with a local base model. It extracts last-token activations
and trains a linear classifier; MLP comparison and causal behavior validation
remain pending. No model assets were available for these three runs, so their
status is **not run**, not zero ASR or zero accuracy.

Primary references: [CaMeL paper](https://arxiv.org/abs/2503.18813) and
[research artifact](https://github.com/google-research/camel-prompt-injection),
[TRL DPO implementation](https://github.com/huggingface/trl/tree/main/trl/trainer).
Mecha's small linear DSL is an independent constrained prototype inspired by
control/data separation, not a replication of the paper's measured results.
