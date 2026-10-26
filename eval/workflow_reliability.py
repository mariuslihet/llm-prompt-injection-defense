"""Offline protocol fault injection; this does not measure real model capability."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from agents.cases import CASE_PATH, resolve_case
from agents.email import run_email
from agents.scenarios import SUITE_SCENARIOS
from packages.policy import compile_policy


class InvalidReplyProvider:
    async def complete(self, messages: list[dict[str, str]], model: str) -> str:
        return "A deliberately unusable protocol reply."


async def run(output: Path) -> dict:
    root = Path(__file__).resolve().parents[1]
    policy = compile_policy((root / "packages/policy/default.yaml").read_text(encoding="utf-8"))
    records = []
    for enabled in (False, True):
        for partition in ("development", "heldout"):
            for variation in range(5):
                for base in SUITE_SCENARIOS:
                    case = resolve_case(base, partition, variation)
                    result = await run_email(
                        InvalidReplyProvider(),
                        "protocol-fault",
                        policy,
                        case.email,
                        scenario_override=case,
                        recover_model_errors=enabled,
                    )
                    records.append(
                        {
                            "recovery": enabled,
                            "case_id": case.id,
                            "run": result.model_dump(mode="json"),
                        }
                    )
    report = {
        "experiment": "offline protocol fault injection",
        "real_model_calls": 0,
        "case_bank": CASE_PATH.name,
        "case_bank_sha256": hashlib.sha256(CASE_PATH.read_bytes()).hexdigest(),
        "records": records,
        "summary": [],
    }
    for enabled in (False, True):
        selected = [r["run"] for r in records if r["recovery"] == enabled]
        report["summary"].append(
            {
                "recovery": enabled,
                "tasks": len(selected),
                "successful_tasks": sum(r["utility_success"] for r in selected),
                "errors": sum(r["status"] == "error" for r in selected),
                "recovered_runs": sum(bool(r["model_recoveries"]) for r in selected),
                "recorded_effects": sum(len(r["effects"]) for r in selected),
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("artifacts/workflow-reliability.json"))
    args = parser.parse_args()
    print(json.dumps(asyncio.run(run(args.output))["summary"]))
