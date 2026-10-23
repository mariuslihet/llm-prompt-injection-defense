"""Import explicit local benchmark exports; never downloads/runs third-party targets.

These are schema adapters, not implementations or evidence of upstream benchmarks.
Agent execution/effect mapping must be supplied for each benchmark environment.
"""

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class BenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    payload: str = Field(max_length=65536)
    expected: str
    source: str


FIELDS = {
    "agentdojo": ("attack", "attacker_goal"),
    "injecagent": ("Attacker Instruction", "Attacker Tool Parameters"),
    "bipia": ("attack", "target"),
    "garak": ("prompt", "detector"),
    "promptfoo": ("prompt", "expected"),
}


def import_export(name: str, path: Path) -> list[BenchmarkCase]:
    if name not in FIELDS:
        raise ValueError("unsupported benchmark export")
    if path.stat().st_size > 20_000_000:
        raise ValueError("benchmark export too large")
    payload_key, expected_key = FIELDS[name]
    records = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("expected JSON array; normalize upstream export explicitly")
    cases = []
    for i, record in enumerate(records):
        if not isinstance(record[payload_key], str):
            raise ValueError("payload must be text")
        cases.append(
            BenchmarkCase(
                id=f"{name}-{i}",
                payload=record[payload_key],
                expected=json.dumps(record[expected_key], sort_keys=True),
                source=name,
            )
        )
    return cases
