"""One-command opt-in model-driven fake email evidence, separate from fixture ASR."""

import argparse
import asyncio
import hashlib
import html
import json
from pathlib import Path

from agents.email import DEFENSES
from agents.scenarios import SCENARIOS, attack_input
from lab.campaigns import RunSpec, execute
from packages.gateway.providers import LocalHFProvider, configured_provider
from packages.policy import compile_policy


async def run(args) -> dict[str, object]:
    provider = (
        LocalHFProvider(str(args.model_path))
        if args.model_path
        else configured_provider(args.provider)
    )
    spec = RunSpec(
        kind="suite" if args.suite else "campaign" if args.campaign else "agent",
        defense=args.defense,
        adaptive_rounds=0 if args.suite else args.adaptive_rounds,
        email=args.email.read_text(encoding="utf-8")
        if args.email
        else attack_input(SCENARIOS[args.scenario], "authority"),
        scenario_id=args.scenario,
        max_turns=args.max_turns,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)

    async def progress(value):
        (args.output.with_suffix(".checkpoint.json")).write_text(
            json.dumps(value, indent=2), encoding="utf-8"
        )
        print(json.dumps({k: v for k, v in value.items() if k != "records"}), flush=True)

    root = Path(__file__).parents[1]
    policy = compile_policy((root / "packages/policy/default.yaml").read_text())
    result = await asyncio.wait_for(
        execute(spec, provider, args.model, policy, "cli", progress), 600
    )
    result["source_sha256"] = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("agents/email.py", "lab/campaigns.py", "packages/gateway/providers.py")
    }
    if args.model_path and (args.model_path / "mecha-manifest.json").is_file():
        result["model_manifest"] = json.loads(
            (args.model_path / "mecha-manifest.json").read_text(encoding="utf-8")
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    args.output.with_suffix(".html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        "<title>Mecha model-agent report</title>"
        '<meta name="viewport" content="width=device-width"><style>body{font:16px system-ui;'
        "max-width:1100px;margin:40px auto;padding:20px}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere}"
        "</style><h1>Model-driven fake email evaluation</h1><p>Invalid runs are inconclusive. "
        "No real email or external tools.</p><h2>Results</h2><pre>"
        + html.escape(json.dumps(result, indent=2))
        + "</pre></html>",
        encoding="utf-8",
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", default="local-hf")
    parser.add_argument("--model-path", type=Path)
    parser.add_argument("--model", default="operator-selected-local-model")
    parser.add_argument("--defense", choices=DEFENSES, default="full-ifc")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--campaign", action="store_true")
    mode.add_argument("--suite", action="store_true")
    parser.add_argument("--adaptive-rounds", type=int, choices=range(4), default=1)
    parser.add_argument(
        "--scenario",
        choices=("launch", "rescheduled", "multilingual", "invoice", "support", "access"),
        default="invoice",
    )
    parser.add_argument("--max-turns", type=int, choices=range(1, 9), default=6)
    parser.add_argument("--email", type=Path)
    parser.add_argument("--output", type=Path, default=Path("artifacts/model-agent.json"))
    report = asyncio.run(run(parser.parse_args()))
    print(json.dumps(report["summary"]))
    raise SystemExit(not all(row["conclusive"] for row in report["summary"]))
