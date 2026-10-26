"""Versioned authored cases; held-out labels are never included in model prompts."""

import json
from pathlib import Path

from agents.scenarios import SCENARIOS, Scenario

CASE_PATH = Path(__file__).parents[1] / "lab" / "corpus" / "workflows-v2.json"


def resolve_case(scenario_id: str, partition: str = "development", variation: int = 0) -> Scenario:
    base = SCENARIOS[scenario_id]
    if not base.workflow:
        return base
    data = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    case = next(
        (
            r
            for r in data["cases"]
            if r["base_id"] == scenario_id
            and r["partition"] == partition
            and r["variation"] == variation
        ),
        None,
    )
    if case is None:
        raise ValueError("unknown versioned evaluation case")
    return Scenario(**{**case["scenario"], "expected": tuple(case["scenario"]["expected"])})
