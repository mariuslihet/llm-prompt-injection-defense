"""Calibrate on disjoint groups and measure a local fine-tuned detector under mutation."""

import argparse
import hashlib
import json
import random
from pathlib import Path

from agents.mock import AGENTS
from lab.corpus import load
from lab.mutators import OPERATORS, mutate
from packages.detectors import LocalClassifier
from packages.detectors.cascade import calibrate
from training.hf_experiments import validate_rows


def run(model_path: Path, data_path: Path) -> dict[str, object]:
    import torch

    torch.set_num_threads(2)
    model = LocalClassifier(str(model_path))
    rows = validate_rows(data_path)
    calibration = [r for r in rows if r["split"] == "calibration"]
    if not calibration:
        raise ValueError("separate calibration split required")
    config = calibrate(
        [model.score(str(r["text"])) for r in calibration if r["label"] == 0],
        [model.score(str(r["text"])) for r in calibration if r["label"] == 1],
        max_fpr=0.05,
    )
    threshold = config["threshold"]
    test = [r for r in rows if r["split"] == "test"]
    attacks = [r for r in test if r["label"] == 1]
    benign = [r for r in test if r["label"] == 0]
    static_misses = sum(model.score(str(r["text"])) < threshold for r in attacks)
    fp = sum(model.score(str(r["text"])) >= threshold for r in benign)
    rng = random.Random(42)
    successes, n = 0, 0
    for attack in load():
        if not any(r["group"] == attack.category for r in attacks):
            continue
        candidates = [attack.payload] + [mutate(attack.payload, rng, op) for op in OPERATORS]
        # Feedback-guided black-box attacker chooses the lowest learned score.
        best = min(candidates, key=model.score)
        successes += model.score(best) < threshold
        n += 1
    return {
        "experiment": "bert-tiny-calibrated-fixture-detector",
        "seed": 42,
        "data_sha256": hashlib.sha256(data_path.read_bytes()).hexdigest(),
        "model_sha256": hashlib.sha256((model_path / "model.safetensors").read_bytes()).hexdigest(),
        "calibration": config,
        "test_attack_n": len(attacks),
        "static_misses": static_misses,
        "static_evasion_rate": static_misses / len(attacks),
        "test_benign_n": len(benign),
        "benign_fp": fp,
        "benign_fpr": fp / len(benign),
        "adaptive_trials": n,
        "adaptive_successes": successes,
        "adaptive_evasion_rate": successes / n,
        "attack_budget": len(OPERATORS) + 1,
        "limits": "Synthetic templates; classification-evasion oracle, not real LLM agent ASR.",
        "targets_available": list(AGENTS),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.model, args.data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))
