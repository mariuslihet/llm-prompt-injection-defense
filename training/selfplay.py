"""Cheap synthetic Naive Bayes baseline, not a transformer fine-tuning result."""

import argparse
import json
import math
import random
import re
from collections import Counter
from pathlib import Path

from eval.harness import benign_tasks
from lab.corpus import CATEGORIES, load
from lab.mutators import OPERATORS, mutate


def tokens(text: str) -> list[str]:
    return re.findall(r"[\w]+|[^\w\s]", text.casefold())[:4096]


class Bayes:
    def __init__(self, rows: list[tuple[str, int]]) -> None:
        self.counts = [Counter(), Counter()]
        self.docs = [0, 0]
        for text, label in rows:
            self.counts[label].update(tokens(text))
            self.docs[label] += 1
        self.vocab = set(self.counts[0]) | set(self.counts[1])

    def score(self, text: str) -> float:
        scores = []
        for label in (0, 1):
            score = math.log((self.docs[label] + 1) / (sum(self.docs) + 2))
            denominator = sum(self.counts[label].values()) + max(1, len(self.vocab))
            for token in tokens(text):
                score += math.log((self.counts[label][token] + 1) / denominator)
            scores.append(score)
        delta = max(-700, min(700, scores[0] - scores[1]))
        return 1 / (1 + math.exp(delta))


def experiment(rounds: int = 4, seed: int = 42) -> dict[str, object]:
    if not 1 <= rounds <= 20:
        raise ValueError("rounds out of bounds")
    rng = random.Random(seed)
    train_attacks = [a for a in load() if a.category in CATEGORIES[:14]]
    holdout = [a for a in load() if a.category in CATEGORIES[14:]]
    tasks = benign_tasks()
    rows = [(a.payload, 1) for a in train_attacks] + [(t["text"], 0) for t in tasks[:100]]
    history = []
    for round_number in range(rounds):
        model = Bayes(rows)
        adaptive_train = [
            min((mutate(a.payload, rng, op) for op in OPERATORS[:-1]), key=model.score)
            for a in train_attacks
        ]
        # Entire categories and the JSON-escape operator are held out of fitting.
        adaptive_test = [mutate(a.payload, rng, "json-escape-split") for a in holdout]
        train_asr = sum(model.score(p) < 0.5 for p in adaptive_train) / len(adaptive_train)
        test_asr = sum(model.score(p) < 0.5 for p in adaptive_test) / len(adaptive_test)
        fpr = sum(model.score(t["text"]) >= 0.5 for t in tasks[100:]) / len(tasks[100:])
        history.append(
            {
                "round": round_number,
                "training_evasion_rate": train_asr,
                "heldout_evasion_rate": test_asr,
                "benign_fpr": fpr,
                "overfit_gap": test_asr - train_asr,
            }
        )
        rows.extend((p, 1) for p in adaptive_train)
    return {
        "experiment": "synthetic-naive-bayes-selfplay",
        "seed": seed,
        "rounds": history,
        "train_categories": list(CATEGORIES[:14]),
        "heldout_categories": list(CATEGORIES[14:]),
        "heldout_operator": "json-escape-split",
        "model": "multinomial NB; not pretrained",
        "limitation": "Fixture grammar and templated benign tasks; not real-model robustness.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("artifacts/selfplay.json"))
    parser.add_argument("--rounds", type=int, default=4)
    args = parser.parse_args()
    report = experiment(args.rounds)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    values = report["rounds"]
    points = " ".join(
        f"{60 + r['round'] * 100},{200 - r['heldout_evasion_rate'] * 160}" for r in values
    )
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="600" height="260" role="img" '
        'aria-label="Held-out evasion rate per self-play round">'
        '<rect width="600" height="260" fill="white"/><text x="20" y="25">'
        "Synthetic NB self-play: held-out evasion rate</text>"
        '<path d="M60 40V200H550" fill="none" stroke="black"/>'
        f'<polyline points="{points}" fill="none" stroke="#267b69" stroke-width="3"/>'
        '<text x="12" y="50">100%</text><text x="20" y="205">0%</text>'
        '<text x="220" y="240">Self-play round</text></svg>'
    )
    args.output.with_suffix(".svg").write_text(svg, encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
