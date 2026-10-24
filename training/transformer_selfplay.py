"""Seeded local transformer retraining with frozen grouped evaluation splits."""

import argparse
import json
import random
from pathlib import Path

from eval.learned import run as evaluate
from lab.corpus import load
from lab.mutators import OPERATORS, mutate
from packages.detectors import LocalClassifier
from training.hf_experiments import run as train
from training.hf_experiments import validate_rows


def experiment(
    model: Path, data: Path, output: Path, rounds: int = 2, seed: int = 42
) -> dict[str, object]:
    if output.exists() or not 1 <= rounds <= 5:
        raise ValueError("fresh output and one to five rounds required")
    import torch

    torch.set_num_threads(2)
    rows = validate_rows(data)
    output.mkdir(parents=True)
    current_model, current_data = model, data
    history = []
    rng = random.Random(seed)
    train_groups = {row["group"] for row in rows if row["split"] == "train"}
    attacks = [attack for attack in load() if attack.category in train_groups]
    for round_number in range(rounds + 1):
        metrics = evaluate(current_model, current_data)
        history.append({"round": round_number, **metrics})
        print(
            json.dumps(
                {
                    "round": round_number,
                    "adaptive_evasion": metrics["adaptive_evasion_rate"],
                    "benign_fpr": metrics["benign_fpr"],
                }
            ),
            flush=True,
        )
        if round_number == rounds:
            break
        predictor = LocalClassifier(str(current_model))
        for attack in attacks:
            candidates = [mutate(attack.payload, rng, operator) for operator in OPERATORS]
            selected = min(candidates, key=predictor.score)
            rows.append({"text": selected, "label": 1, "group": attack.category, "split": "train"})
        current_data = output / f"round-{round_number + 1}.jsonl"
        current_data.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        destination = output / f"round-{round_number + 1}"
        train("classifier", current_model, current_data, destination, seed)
        current_model = destination / "model"
    report = {
        "experiment": "bert-tiny-transformer-selfplay",
        "seed": seed,
        "rounds": history,
        "limits": "Frozen grouped fixtures and small mutation budget; not real agent robustness.",
    }
    (output / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=2)
    args = parser.parse_args()
    experiment(args.model, args.data, args.output, args.rounds)
