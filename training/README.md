# Research experiments

All inputs must be sample-data fixtures. No script enables tool execution from
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

Optional transformer research was executed locally. Model revision/file hashes
are in docs/reports/*-model-manifest.json; weights and trained artifacts remain
ignored under artifacts/. Install with `uv sync --frozen --extra research`.
Training/inference always uses local_files_only and trust_remote_code=false.

```sh
uv run --extra research python -m training.data --output artifacts/training
uv run --extra research python -m training.hf_experiments classifier --model artifacts/models/bert-tiny --data artifacts/training/classifier.jsonl --output artifacts/classifier-fresh
uv run --extra research python -m training.transformer_selfplay --model artifacts/classifier-calibrated-42/model --data artifacts/training/classifier.jsonl --output artifacts/selfplay-fresh --rounds 2
uv run --extra research python -m training.bounded_data artifacts/training/hierarchy.jsonl artifacts/training/hierarchy-bounded.jsonl
uv run --extra research python -m training.hf_experiments dpo --model artifacts/models/smollm2-135m --data artifacts/training/hierarchy-bounded.jsonl --output artifacts/dpo-fresh --max-steps 4
uv run --extra research python -m training.behavior_probe --model artifacts/models/smollm2-135m --output artifacts/behavior-probe-fresh
uv run --extra multimodal python -m training.hidden_channels --output artifacts/hidden-channels-fresh
```

Use fresh output paths. See docs/reports/phase-4.md for the measured results and
negative findings. Classifier training is not real-agent ASR. DPO preference
likelihoods are not a comprehensive capability benchmark. The behavior-probe
run produced no valid actions and could not train either probe; no accuracy is
claimed. Hidden PDF/PNG metadata experiments do not perform OCR.

For the model-driven natural-language email agent and adaptive attacker, see
[the private MVP runbook](../docs/MVP.md). The deterministic fixture corpus and
live-model evidence are reported separately.

Primary references: [CaMeL paper](https://arxiv.org/abs/2503.18813) and
[research artifact](https://github.com/google-research/camel-prompt-injection),
[TRL DPO implementation](https://github.com/huggingface/trl/tree/main/trl/trainer).
Mecha's small linear DSL is an independent constrained prototype inspired by
control/data separation, not a replication of the paper's measured results.
