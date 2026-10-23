# API and integrations

Run the gateway, then visit http://127.0.0.1:8000/docs for generated request and
response schemas. Except /health and generated docs, endpoints require a
tenant Bearer key; x-api-key is accepted for Anthropic text requests. Missing
keys return 401, roles 403, validation 422, limits 429, provider failure 502.

| Route | Role | Purpose |
| --- | --- | --- |
| POST /v1/chat/completions | operator/admin | OpenAI text response or buffered SSE |
| POST /v1/messages | operator/admin | Anthropic text response or buffered SSE |
| POST /mcp | operator/admin | mock JSON-RPC initialize/list/summarize subset |
| POST /tools/call | operator/admin | explicit operator-intent mock tool call |
| POST /approvals | admin | issue action-bound, 300-second, one-use grant |
| GET /audit, /export/cef | authenticated | tenant metadata / SIEM export |
| GET /policy | authenticated | active policy and revision history |
| POST /policy/stage, /policy/promote | admin | validate, stage, activate or roll back |
| GET/POST /tenants | platform admin | list/create process-local tenants |
| GET /arena/levels, /arena/leaderboard | authenticated | fake-data challenges and scores |
| POST /arena/submit | operator/admin | run fixture mutation only |
| POST /arena/review/{digest}, GET /arena/reviewed | admin | review/export corpus candidates |

The proxy supports a strict text subset, not all provider request fields.
Client system messages are rejected because the server owns trusted system
authority. Tool calls, multimodal blocks and provider-specific extra parameters
are not forwarded. SSE starts only after full output sanitation. Mock token
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
remain mock. No real provider connection was tested in this repository run.

MCP Catalog validates canonical hash pins, description heuristics, server
permission scope and cross-server name shadowing. Its HMAC helper authenticates
a trusted manifest; it is not a public-key signing system. /mcp serves local
mock tools only and is not a certified remote MCP proxy.

SIEM: /audit exports structured JSON and /export/cef escapes delimiters.
`packages.telemetry.export.webhook` supports Slack and PagerDuty metadata with
MECHA_ALLOW_WEBHOOKS=1 plus an explicit HTTPS host allowlist. It is an opt-in
integration function, not an automatically connected incident destination.
`packages.telemetry.otel.configure` configures the optional OTel SDK/exporter;
automatic spans and production collector verification remain pending.
