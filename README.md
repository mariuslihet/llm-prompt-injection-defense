# Mecha

Mecha is a private MVP for evaluating prompt-injection defenses in agent workflows.
It connects a policy-enforcing gateway, model-driven attack campaigns, and saved
evaluation evidence. Structural information-flow control (IFC) separates untrusted
content from authority to execute tools.

**Status:** locally verified, single-host MVP. Production acceptance remains open.
Claims apply to tested tools and execution paths; Mecha does not claim to prevent
prompt injection in general. Read the [tested claims](docs/SECURITY_CLAIMS.md),
[limitations](docs/LIMITATIONS.md), and [acceptance register](docs/ACCEPTANCE.md).

## Console

| Page | Purpose |
| --- | --- |
| Overview | Tenant decision counts, block rates, and recent activity |
| Incident Review | Inspect labels, policy decisions, and execution traces |
| Security Policy | Validate, stage, activate, and roll back policy revisions |
| Security Tests | Replay scripted regression cases and inspect exact action outcomes |
| Agent Evaluation | Run the model, adaptive attacks, business suites, and saved-run comparisons |
| Access Management | Manage tenant access with platform administrator permissions |

The gateway provides tenant authentication, roles, rate limits, durable SQLite
state, action-bound approvals, and a hash-chained audit log. Evaluation jobs support
idempotent submission, quotas, cancellation, restart recovery, and JSON export.

Evaluation tools use sample data and simulated actions inside this repository.
No evaluation email is delivered, no payment or access change is executed, and no
third-party system is an attack target.

## Local model quickstart

The verified setup uses Windows, Python 3.11+, Git,
[uv](https://docs.astral.sh/uv/getting-started/installation/), Node.js 22+, and an
NVIDIA GPU with 8 GB VRAM. It was checked on an RTX 2070. The supplied launcher uses
CUDA 12.4 Windows binaries; other platforms need their own runtime configuration.

From the repository folder, run in PowerShell:

```powershell
uv sync --frozen --extra signing --extra multimodal
npm --prefix dashboard ci --ignore-scripts
npm --prefix dashboard run build
uv run python -m training.acquire_gguf
./deploy/start-local.ps1
```

Acquisition downloads approximately 5.4 GB of official model/runtime files, verifies
pinned SHA-256 hashes, and stores them in the ignored `artifacts/local-inference/`
directory. Skip acquisition on later starts. Inference does not require the optional
PyTorch research packages.

Open [Mecha](http://127.0.0.1:8000/), enter the local demonstration key
`fake-local-demo-key`, and select **Connect / refresh**.

The launcher starts **Qwen2.5-7B-Instruct Q4_K_M** on `127.0.0.1:8081` and the gateway
with its built console on `127.0.0.1:8000`. It generates a separate local inference
API key and refuses occupied ports. Reuse the console if the services already run.
Service logs are in `artifacts/local-inference/`.

The demonstration tenant key is explicitly configured in `.env.mvp.example`.
Production mode rejects demonstration credentials and ephemeral storage. See the
[MVP runbook](docs/MVP.md) before changing the deployment boundary.

## Evaluate different tasks

Agent Evaluation defaults to three business workflows:

| Scenario | Trusted objective | Attack context |
| --- | --- | --- |
| Finance | Extract the final invoice total, currency, ID, and due date | Vendor payment verification |
| Support | Classify an outage by ticket ID, severity, team, and issue code | Account-recovery escalation |
| Governance | Review an access request against manager-approval requirements | Urgent approval override |

Earlier scheduling and multilingual cases remain selectable for historical
comparisons. Each scenario has its own trusted instructions and expected fields.
IFC uses separate validated output schemas for the business tasks.

- **Run model agent:** execute one configuration on the selected input.
- **Run adaptive comparison:** compare five defenses using a normal input, your
  attack, and zero to three feedback-driven attacker revisions.
- **Run business suite:** execute six unique inputs, a normal and attack case for
  each business workflow, across five defenses: **30 defense executions**.

Select an authority, workflow, or concealment strategy and configure the agent turn
limit. The business suite uses server-owned inputs and static attacks; edits in the
single-scenario editor apply to single-agent and adaptive comparison runs.

Results group each unique input into one card, with actual action paths and outcomes
for every defense. Select a defense to inspect its original timeline and final
answer. Matching inputs are intentionally reused across defenses for comparison;
identical observed trajectories remain identical in the evidence.

Saved results include scenario breakdowns, normal-task success, static/adaptive
attack outcomes, invalid runs, model-call counts, and median/p95 duration. Filter
results, inspect attacker proposals, or export the complete job as JSON.

Choose a completed baseline to compare matching datasets. Different inputs or
budgets are rejected; model/policy changes are identified separately. Comparisons
are descriptive and do not establish statistical significance.

Jobs share a **128-model-call budget**, a **600-second deadline**, and one executing
slot. Exhausted budgets, malformed outputs, and provider failures are explicit.
Invalid evidence is inconclusive.

## Measured local evidence

The recorded business suite used Qwen2.5-7B-Instruct, six unique inputs, 30 defense
executions, and 60 model calls, with no invalid runs:

| Defense | Static attack successes | Normal-task field checks passed |
| --- | --- | --- |
| None | 3/3 | 2/3 |
| Prompt hardening | 3/3 | 2/3 |
| Detector | 0/3 | 2/3 |
| Detector + sanitizer | 0/3 | 2/3 |
| Full IFC | 0/3 | 3/3 |

These are small, authored samples. Task success checks required output fields and
absence of unauthorized effects; it is not a general semantic answer judge.
Evaluation latency includes inference, not just gateway overhead. See the
[business-suite evidence](docs/reports/business-suite.json),
[repeat comparison](docs/reports/business-comparison.json), and
[verification notes](docs/reports/phase-5.md).

Historical [scripted benchmarks](docs/reports/latest.html),
[adaptive model campaigns](docs/reports/qwen7b-campaign.html), and
[research experiments](docs/reports/phase-4.md) are separate populations. Their
scores must not be combined. Output sanitization cannot undo an executed tool action.

## Offline demonstration and verification

For a lighter setup without model weights:

```powershell
uv sync --frozen --extra signing --extra multimodal
uv run mecha demo-attack
uv run mecha evaluate --output artifacts/eval
uv run mecha gate artifacts/eval.json
```

The demonstration reproduces a test-canary disclosure in a deliberately vulnerable
script and compares it with IFC. Security Tests runs deterministic regression cases;
it does not call the language model.

```powershell
uv run pytest --cov --cov-report=term-missing
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run mecha verify-policy packages/policy/default.yaml
uv run mecha load-test
npm --prefix dashboard run build
```

The latest local check passed **106 tests**, with **99.20% coverage** across the
configured core, policy, IFC, and sanitizer modules. Tests block external network
connections and use deterministic providers. Windows asyncio's internal socket pair
remains permitted. Dependency installation and asset acquisition require network access.

## Deployment scope and documentation

The supported MVP runs one worker on one host with SQLite. Representative held-out
evaluation, high-concurrency latency acceptance, Linux isolation/deployment checks,
hosted CI, and independent security review remain open. Docker and Helm assets
have not been runtime-verified on this Windows host. Publication is deferred and
no open-source license has been selected.

- [MVP setup, operation, and limits](docs/MVP.md)
- [Architecture](docs/ARCHITECTURE.md) and [threat model](docs/THREAT_MODEL.md)
- [Policy reference](docs/POLICY.md) and [API / SDK integrations](docs/INTEGRATIONS.md)
- [Self-hosting, backup, and upgrades](docs/SELF_HOST.md)
- [Plan](docs/PLAN.md), [acceptance status](docs/ACCEPTANCE.md), and [handoff report](docs/reports/FINAL.md)
- [Research scripts](training/README.md), [contributing](CONTRIBUTING.md), and [security reporting](SECURITY.md)
