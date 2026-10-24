"""Reproducible bounded evolutionary campaign against fake-data agents."""

import argparse
import json
from pathlib import Path

from agents.mock import AGENTS
from eval.harness import benign, wilson
from lab.attackers.evolution import evolve
from lab.corpus import load


def run(output: Path, seed: int = 42, budget: int = 16) -> dict[str, object]:
    rows, logs = [], []
    for config in ("none", "detector", "detector-sanitizer", "full-ifc"):
        success, attempts = 0, 0
        for agent in AGENTS:
            for attack in load():
                result, trace = evolve(agent, attack, config, seed=seed, budget=budget)
                success += attack.oracle.succeeds(result)
                attempts += len(trace)
                logs.append({"config": config, "agent": agent, "attack": attack.id, "trace": trace})
        n = len(AGENTS) * len(load())
        rows.append(
            {
                "config": config,
                "successes": success,
                "trials": n,
                "asr": success / n,
                "ci95": wilson(success, n),
                "attempts": attempts,
                "benign": benign(config),
            }
        )
    report = {
        "experiment": "evolutionary-fixture-campaign",
        "seed": seed,
        "budget": budget,
        "population": 4,
        "rows": rows,
        "limits": "Synthetic grammar and correlated templates only.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    output.with_name(output.stem + "-campaigns.jsonl").write_text(
        "\n".join(json.dumps(row) for row in logs) + "\n", encoding="utf-8"
    )
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("artifacts/evolutionary.json"))
    args = parser.parse_args()
    report = run(args.output)
    print(json.dumps(report))
    if any(row["config"] == "full-ifc" and row["successes"] for row in report["rows"]):
        raise SystemExit(1)
