# API and integrations

Run the gateway, then visit http://127.0.0.1:8000/docs for generated request and
response schemas. Except /health and generated docs, endpoints require a
tenant Bearer key; x-api-key is accepted for Anthropic text requests. Missing
keys return 401, roles 403, validation 422, limits 429, provider failure 502.

| Route | Role | Purpose |
| --- | --- | --- |
| POST /v1/chat/completions | operator/admin | OpenAI text response or buffered SSE |
| POST /v1/messages | operator/admin | Anthropic text response or buffered SSE |
| POST /mcp | operator/admin | simulated JSON-RPC initialize/list/summarize subset |
| POST /tools/call | operator/admin | explicit operator-intent simulated tool call |
| POST /approvals | admin | issue action-bound, 300-second, one-use grant |
| GET /audit, /export/cef | authenticated | tenant metadata / SIEM export |
| GET /policy | authenticated | active policy and revision history |
| POST /policy/stage, /policy/promote | admin | validate, stage, activate or roll back |
| GET/POST /tenants | platform admin | list/create durable tenant key hashes |
| GET /arena/levels, /arena/leaderboard | authenticated | sample-data challenges and scores |
| POST /arena/submit | operator/admin | run fixture mutation only |
| POST /arena/review/{digest}, GET /arena/reviewed | admin | review/export corpus candidates |

The proxy supports a strict text subset, not all provider request fields.
Client system messages are rejected because the server owns trusted system
authority. Tool calls, multimodal blocks and provider-specific extra parameters
are not forwarded. SSE starts only after full output sanitation. Simulated token
usage is unavailable and represented as zero; do not use it for cost billing.

The gateway model proxy alone does not secure tools a client executes elsewhere.
Use packages.ifc.Interpreter with trusted server-assigned Values and a restricted
Program. `plan(request)` only accepts a trusted task name. `quarantine(value)`
returns a typed summary without a tool handle. `TaintSession.observe` and
`authorize` provide a conservative fallback when fine-grained IFC is unavailable.
Do not route model-generated tool arguments to /tools/call: that endpoint
represents the authenticated human operator's explicit intent.

Python SDK: `packages.sdk_python.Mecha(base_url, api_key)`, async `complete`,
`stream` (SSE JSON data), `close`. TypeScript SDK: packages/sdk-ts/src/index.ts.
Neither SDK grants model output authority to call tools.

Providers: set MECHA_PROVIDER to openai/anthropic/ollama/vllm, MECHA_ALLOW_NETWORK=1,
credentials and model explicitly. Local provider base URLs are operator-owned
configuration; never accept an endpoint from an untrusted request. Defaults
use the offline provider. The local 7B provider has been tested; hosted-provider interoperability remains unverified.

MCP Catalog validates canonical hash pins, description heuristics, server
permission scope and cross-server name shadowing. Optional trusted_signers enforce per-server Ed25519 signatures in addition to
hash pins; the legacy HMAC helper remains available. /mcp serves local
simulated tools only and is not a certified remote MCP proxy.

SIEM: /audit exports structured JSON and /export/cef escapes delimiters.
`packages.telemetry.export.webhook` supports Slack and PagerDuty metadata with
MECHA_ALLOW_WEBHOOKS=1 plus an explicit HTTPS host allowlist. It is an opt-in
integration function, not an automatically connected incident destination.
`packages.telemetry.otel.configure` configures the optional OTel SDK/exporter;
metadata-only decision spans are emitted; actual collector delivery remains
unverified. Configure MECHA_OTEL_ENDPOINT and MECHA_ALLOW_TELEMETRY=1 explicitly.

## Model-driven MVP APIs

See docs/MVP.md for /lab/config, authenticated durable /lab/jobs, tenant-scoped
job retrieval and operator cancellation. /ready reports local storage readiness.
The built console and /api-prefixed API can share one origin by configuring
MECHA_DASHBOARD_PATH. /ifc/run returns typed execution traces; /incidents/{digest}
replays metadata for the authenticated tenant; /metrics aggregates stored actions.
GET /arena/pending exposes only the current admin tenant's sample-data queue.

Python SDK start_agent, job and cancel_job wrap the job APIs. TypeScript
startAgent and job return unknown JSON requiring caller validation. Provider
exceptions are redacted; failed model runs appear explicitly in result records.


## Review workspace API

All routes require a tenant bearer key and enforce tenant isolation.

| Endpoint | Role | Behavior |
| --- | --- | --- |
| GET /reviews | viewer/operator/admin | Latest 100 requests, role and current policy digest |
| POST /reviews | operator/admin | Fixed tool/argument contract plus title (100), justification (1000), priority normal/high/urgent |
| POST /reviews/{id}/notes | operator/admin | Add a nonempty note up to 1000 characters |
| POST /reviews/{id}/withdraw | operator/admin | Withdraw an unexpired pending request with a note |
| POST /reviews/{id}/decision | admin | Strict boolean approve plus optional note (1000); existing binding/expiry constraints apply |

The console requires a decision note; the API keeps optional notes for backward
compatibility. Request history is capped at 100 entries; comments reserve space
for state transitions. Labels are assigned by the server. Titles, notes and
priority cannot grant authority. Role attribution is tenant-role attribution, not
individual identity. Reviews and exports contain sample data only.

## Focused evaluation API

POST /lab/jobs accepts an optional title (100 characters) and selected_defenses
(list of 1–5 distinct supported names). Selection applies to campaign/suite runs;
single-agent runs use defense. GET /lab/jobs includes title and kind; GET a job
returns its saved spec for deliberate reuse. Campaigns retain 128 model calls;
suites reserve 6 × selected-defense count × max(2, max_turns) calls. The 600-second
deadline, tenant quotas and single-worker execution remain unchanged.
Dataset fingerprints include the defense selection/order but exclude the title.
