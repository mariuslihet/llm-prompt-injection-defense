"""Documented command-line interface for local, reproducible research."""

import argparse
import json
from dataclasses import asdict
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(prog="mecha")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo-attack")
    sub.add_parser("corpus")
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--output", type=Path, default=Path("artifacts/eval"))
    evaluate.add_argument("--seed", type=int, default=42)
    evaluate.add_argument("--budget", type=int, default=8, choices=range(1, 65))
    policy = sub.add_parser("verify-policy")
    policy.add_argument("path", type=Path)
    flow = sub.add_parser("verify-flow")
    flow.add_argument("program", type=Path)
    flow.add_argument("inputs", type=Path)
    flow.add_argument("--policy", type=Path, default=Path("packages/policy/default.yaml"))
    gate = sub.add_parser("gate")
    gate.add_argument("report", type=Path)
    load = sub.add_parser("load-test")
    load.add_argument("--requests", type=int, default=1000)
    load.add_argument("--output", type=Path, default=Path("artifacts/load.json"))
    args = parser.parse_args()
    if args.command == "demo-attack":
        from agents.mock import run_vulnerable
        from eval.harness import defend
        from lab.corpus import load

        attack = next(a for a in load() if a.category == "exfil-email")
        vulnerable = run_vulnerable("email-calendar", attack.payload)
        protected = defend("email-calendar", attack.payload, "full-ifc")
        print(
            json.dumps(
                {
                    "target": "sandbox mock only",
                    "attack": attack.id,
                    "vulnerable": asdict(vulnerable),
                    "protected": asdict(protected),
                    "baseline_success": attack.oracle.succeeds(vulnerable),
                    "protected_success": attack.oracle.succeeds(protected),
                },
                indent=2,
            )
        )
        if not attack.oracle.succeeds(vulnerable) or attack.oracle.succeeds(protected):
            raise SystemExit(1)
    elif args.command == "corpus":
        from lab.corpus import write

        write()
    elif args.command == "evaluate":
        from eval.harness import evaluate

        report = evaluate(args.output, args.seed, args.budget)
        print(json.dumps({"report": str(args.output), "evidence": report["evidence"]}))
    elif args.command == "verify-policy":
        from packages.policy import compile_policy, verify

        errors = verify(compile_policy(args.path.read_text(encoding="utf-8")))
        print(json.dumps({"errors": errors}))
        raise SystemExit(bool(errors))
    elif args.command == "verify-flow":
        from packages.core import Value
        from packages.ifc import Program
        from packages.ifc.analysis import analyze
        from packages.policy import compile_policy

        program = Program.model_validate_json(args.program.read_text(encoding="utf-8"))
        inputs = {
            name: Value.model_validate(value)
            for name, value in json.loads(args.inputs.read_text(encoding="utf-8")).items()
        }
        result = analyze(program, inputs, compile_policy(args.policy.read_text(encoding="utf-8")))
        print(result.model_dump_json(indent=2))
        raise SystemExit(bool(result.violations))
    elif args.command == "gate":
        from eval.gates import check

        errors = check(json.loads(args.report.read_text(encoding="utf-8")))
        print(json.dumps({"errors": errors}))
        raise SystemExit(bool(errors))
    elif args.command == "load-test":
        import asyncio

        from eval.load import run

        report = asyncio.run(run(args.requests))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report))
        raise SystemExit(report["p95_ms"] >= 50)


if __name__ == "__main__":
    main()
