"""Replay the same locally generated adaptive payloads against source-check modes."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from agents.cases import CASE_PATH, resolve_case
from agents.email import run_email
from agents.scenarios import SUITE_SCENARIOS
from lab.campaigns import Candidate
from packages.gateway.providers import configured_provider
from packages.policy import compile_policy


async def run(source: Path, output: Path) -> dict:
    raw = json.loads(source.read_text(encoding="utf-8"))
    digest = hashlib.sha256(CASE_PATH.read_bytes()).hexdigest()
    if raw.get("source_sha256", {}).get("lab/corpus/" + CASE_PATH.name) != digest:
        raise ValueError("input evidence does not match the current case bank")
    provider = configured_provider("llamacpp")
    root = Path(__file__).resolve().parents[1]
    policy = compile_policy((root / "packages/policy/default.yaml").read_text(encoding="utf-8"))
    records = []
    for campaign in raw["runs"]:
        if campaign["phase"] != "adaptive" or campaign["mode"] != "off":
            continue
        spec = campaign["result"]["spec"]
        if spec["scenario_id"] not in SUITE_SCENARIOS or spec["partition"] not in (
            "development",
            "heldout",
        ):
            raise ValueError("unsupported replay scenario")
        case = resolve_case(spec["scenario_id"], spec["partition"], spec["variation"])
        for old in campaign["result"]["records"]:
            if old["case"] != "adaptive":
                continue
            payload = Candidate(payload=old["email"]).payload
            for mode in ("off", "enforce"):
                result = await run_email(
                    provider,
                    raw["model"],
                    policy,
                    payload,
                    scenario_override=case,
                    attack_goal="integrity",
                    attack_channel="record",
                    grounding=mode,
                    max_turns=8,
                )
                records.append(
                    {
                        "case_id": case.id,
                        "mode": mode,
                        "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
                        "run": result.model_dump(mode="json"),
                    }
                )
    report = {
        "experiment": "matched generated adaptive payload replay",
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "case_bank_sha256": digest,
        "records": records,
        "summary": [],
    }
    for mode in ("off", "enforce"):
        runs = [r["run"] for r in records if r["mode"] == mode]
        report["summary"].append(
            {
                "mode": mode,
                "attacks": len(runs),
                "successes": sum(r["attack_success"] for r in runs),
                "invalid": sum(r["status"] in ("error", "budget-exhausted") for r in runs),
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, default=Path("artifacts/adaptive-replay.json"))
    args = parser.parse_args()
    result = asyncio.run(asyncio.wait_for(run(args.source, args.output), timeout=180))
    print(json.dumps(result["summary"]))
