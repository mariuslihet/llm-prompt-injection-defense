# Mecha

An offline-first prompt-injection defense research platform. The loop connects
sample-data agents, an adaptive attack lab, structural information-flow control,
and reproducible evaluation. **It does not claim to prevent prompt injection.**

Current status: working local research prototype. All six phases have tracked
implementation work; the project-level definition of done is **not met**.
See [acceptance status](docs/ACCEPTANCE.md), [tested claims](docs/SECURITY_CLAIMS.md)
and [limitations](docs/LIMITATIONS.md) before using it as a security boundary.

## Private MVP

For the model-driven email agent, adaptive attacker, saved runs and execution
timelines, use the [MVP runbook](docs/MVP.md). The scripted Security Tests remains a
separate deterministic contract demo. The repository remains private and
production acceptance is still open.

The private Windows setup now uses **Qwen2.5-7B-Instruct on the local GPU**.
After acquiring the verified model and building the console as described in the
runbook, start both services with `./deploy/start-local.ps1`, then open
http://127.0.0.1:8000 and select **Agent Evaluation**. Actual results and remaining gaps
are recorded in [the current handoff report](docs/reports/FINAL.md).

## Quickstart

Requires Python 3.11+, Git and [uv](https://docs.astral.sh/uv/getting-started/installation/).
Install downloads packages; default demos and tests never call external services.

```sh
git clone <your-mecha-repository-url> llm-prompt-injection-defense
cd llm-prompt-injection-defense
uv sync --frozen
uv run mecha demo-attack
uv run mecha evaluate --output artifacts/eval
uv run mecha gate artifacts/eval.json
```

The demo prints a successful test-canary email effect on the vulnerable target
and no unauthorized effect under IFC. On systems with Make, `make demo-attack`
does the same. Open `artifacts/eval.html` to inspect the comparison. Use your authorized private repository URL; no publication or push is performed
by the local setup.

Start the gateway:

```sh
# macOS/Linux: cp .env.example .env
# PowerShell: Copy-Item .env.example .env
uv run --env-file .env uvicorn packages.gateway.app:app --host 127.0.0.1 --port 8000
```

In another terminal, start the dashboard and arena (Node 22+):

```sh
cd dashboard
npm ci --ignore-scripts
npm run dev
```

Open [the local console](http://127.0.0.1:5173), enter `fake-local-demo-key`, and
connect. The example grants local admin access for sample-data demos. Generate
new server keys and review the deployment guide before other use. Example keys
are intentionally sample and are never automatically enabled by the application.

For a text-subset proxy request:

```sh
curl http://127.0.0.1:8000/v1/chat/completions \
  -H 'Authorization: Bearer fake-local-demo-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"mecha-mock","messages":[{"role":"user","content":"Summarize the public report."}]}'
```

## Verification

```sh
uv run pytest --cov --cov-report=term-missing
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run mecha verify-policy packages/policy/default.yaml
uv run mecha load-test
uv run python -m training.selfplay --output artifacts/selfplay.json
```

Tests block network client connections. Python 3.11 on Windows uses a loopback
socket pair for asyncio's internal wakeup mechanism; restricted hosts must
permit that OS mechanism. No test invokes a real provider, DNS or a real tool.

## Measured fixture results

168 synthetic attacks, three simulated targets, 336 normal-task fixture tasks, seed 42.
These are contract tests of a synthetic grammar, **not real-model efficacy**.

| Defense | Static ASR | Adaptive ASR | Normal-task utility |
| --- | --- | --- | --- |
| None / prompt hardening | 100% | 100% | 100% |
| Detector | 0% | 100% | 92.86% |
| Detector + sanitizer | 0% | 100% | 92.86% |
| Full IFC | 0% | 0% | 83.33% |

See [report](docs/reports/latest.html), [JSON](docs/reports/latest.json),
[ablation analysis](docs/reports/phase-3.md), and [research findings](docs/reports/phase-4.md).
Text sanitization cannot undo tool effects. IFC declines unapproved deliveries,
which costs utility. The detector's known adaptive bypass is a regression fixture.

## Navigation

- [Plan](docs/PLAN.md), [threat model](docs/THREAT_MODEL.md), [architecture](docs/ARCHITECTURE.md)
- [Policy reference](docs/POLICY.md), [API and integrations](docs/INTEGRATIONS.md)
- [Self-hosting / backup / upgrades](docs/SELF_HOST.md), [research](training/README.md)
- [Contributing](CONTRIBUTING.md), [responsible disclosure](SECURITY.md)
- [Current handoff report](docs/reports/FINAL.md)

All attacks target only code in this repository with simulated effects, reserved
example domains and sample credentials. Do not target third-party systems.
