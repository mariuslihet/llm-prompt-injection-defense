"""Bounded local source-check ablation; invalid runs never establish protection."""

import argparse
import asyncio
import hashlib
import json
import statistics
from pathlib import Path

from agents.cases import resolve_case
from agents.scenarios import SUITE_SCENARIOS, attack_input
from lab.campaigns import RunSpec, execute
from packages.gateway.providers import configured_provider
from packages.policy import compile_policy


def summarize(records: list[dict]) -> dict:
    attacks = [r for r in records if r["case"] != "benign"]
    normal = [r for r in records if r["case"] == "benign"]
    times = sorted(r["run"]["duration_ms"] for r in records)
    return {
        "attack_successes": sum(r["run"]["attack_success"] for r in attacks),
        "attack_trials": len(attacks),
        "adaptive_successes": sum(
            r["run"]["attack_success"] for r in records if r["case"] == "adaptive"
        ),
        "adaptive_trials": sum(r["case"] == "adaptive" for r in records),
        "normal_successes": sum(r["run"]["utility_success"] for r in normal),
        "normal_trials": len(normal),
        "invalid_runs": sum(r["run"]["status"] in {"error", "budget-exhausted"} for r in records),
        "withheld_runs": sum(
            r["run"].get("error_code") == "source_validation_failed" for r in records
        ),
        "corrected_answers": sum(
            r["run"]["outcome_details"].get("grounding", {}).get("status") == "corrected"
            for r in records
        ),
        "normal_corrections": sum(
            r["run"]["outcome_details"].get("grounding", {}).get("status") == "corrected"
            for r in normal
        ),
        "model_calls": sum(r["run"]["model_calls"] for r in records),
        "p50_ms": statistics.median(times) if times else None,
        "p95_ms": times[(95 * len(times) + 99) // 100 - 1] if times else None,
    }


async def run(args: argparse.Namespace) -> dict:
    root = Path(__file__).resolve().parents[1]
    provider = configured_provider(args.provider)
    policy = compile_policy((root / "packages/policy/default.yaml").read_text(encoding="utf-8"))
    report = {
        "status": "running",
        "seed": 42,
        "model": args.model,
        "partition": args.partition,
        "variations": args.variations,
        "adaptive_rounds": args.adaptive_rounds,
        "runs": [],
        "summary": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save() -> None:
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    async def progress(value: dict) -> None:
        pass

    async def campaign() -> None:
        fingerprints: dict[int, str] = {}
        for mode in ("off", "shadow", "enforce"):
            for variation in args.variations:
                spec = RunSpec(
                    kind="suite",
                    title=f"Source checks {mode}",
                    grounding=mode,
                    selected_defenses=("full-ifc",),
                    adaptive_rounds=0,
                    max_turns=8,
                    partition=args.partition,
                    variation=variation,
                    attack_goal="integrity",
                    attack_channel="record",
                )
                result = await execute(
                    spec, provider, args.model, policy, "local-ablation", progress
                )
                digest = result["dataset_digest"]
                if variation in fingerprints and fingerprints[variation] != digest:
                    raise ValueError("static ablation inputs do not match")
                fingerprints[variation] = digest
                report["runs"].append({"phase": "static", "mode": mode, "result": result})
                save()
                print(
                    json.dumps(
                        {
                            "phase": "static",
                            "mode": mode,
                            "variation": variation,
                            "completed": len(report["runs"]),
                        }
                    ),
                    flush=True,
                )
            for base in SUITE_SCENARIOS:
                case = resolve_case(base, args.partition, args.variations[0])
                spec = RunSpec(
                    kind="campaign",
                    title=f"Adaptive source checks {mode}",
                    grounding=mode,
                    selected_defenses=("full-ifc",),
                    adaptive_rounds=args.adaptive_rounds,
                    scenario_id=base,
                    max_turns=8,
                    partition=args.partition,
                    variation=args.variations[0],
                    attack_goal="integrity",
                    attack_channel="record",
                    email=attack_input(case, "authority", "integrity"),
                )
                result = await execute(
                    spec, provider, args.model, policy, "local-ablation", progress
                )
                report["runs"].append({"phase": "adaptive", "mode": mode, "result": result})
                save()
                print(
                    json.dumps(
                        {
                            "phase": "adaptive",
                            "mode": mode,
                            "scenario": base,
                            "completed": len(report["runs"]),
                        }
                    ),
                    flush=True,
                )

    try:
        await asyncio.wait_for(campaign(), timeout=600)
        report["status"] = "completed"
    except Exception:
        report["status"] = "incomplete"
        save()
        raise
    for phase in ("static", "adaptive"):
        for mode in ("off", "shadow", "enforce"):
            selected = [r for r in report["runs"] if r["phase"] == phase and r["mode"] == mode]
            records = [record for r in selected for record in r["result"]["records"]]
            row = summarize(records)
            row.update(
                phase=phase,
                mode=mode,
                conclusive=all(s["conclusive"] for r in selected for s in r["result"]["summary"]),
            )
            report["summary"].append(row)
    report["source_sha256"] = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in (
            "packages/ifc/grounding.py",
            "agents/email.py",
            "agents/workflows.py",
            "lab/campaigns.py",
            "lab/corpus/workflows-v2.json",
        )
    }
    report["limits"] = (
        "Locally authored related cases. Adaptive proposals may differ across modes. "
        "Source agreement is not source truth. Enforce covers configured structured fields only."
    )
    save()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=("llamacpp", "mock"), default="llamacpp")
    parser.add_argument("--model", default="Qwen2.5-7B-Instruct")
    parser.add_argument("--partition", choices=("development", "heldout"), default="development")
    parser.add_argument(
        "--variations", type=int, nargs="+", choices=range(5), default=[0, 1, 2, 3, 4]
    )
    parser.add_argument("--adaptive-rounds", type=int, choices=(0, 1), default=1)
    parser.add_argument("--output", type=Path, default=Path("artifacts/source-check-ablation.json"))
    args = parser.parse_args()
    if len(args.variations) != len(set(args.variations)):
        parser.error("variations must be distinct")
    result = asyncio.run(run(args))
    print(json.dumps(result["summary"]))
    raise SystemExit(not all(row["conclusive"] for row in result["summary"]))
