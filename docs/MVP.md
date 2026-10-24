# Private MVP runbook

Status: the model-driven MVP is under local verification. It is not approved for
public exposure. Keep it private per the operator's 2026-10-24 decision.

## Supported boundary

Single Python worker, local SQLite/WAL, tenant Bearer keys, same-origin console,
bounded durable background jobs and sample email tools. The model decides tool
actions from natural-language input. The model-driven Agent Evaluation is separate
from the deterministic scripted Security Tests. Neither can send real emails, run a shell
or fetch attacker-controlled URLs. The gateway's text API does not automatically
protect tools that a client executes outside Mecha.

## Start locally

From the repository, install the locked packages and build:

```powershell
uv sync --frozen --extra multimodal --extra signing
npm --prefix dashboard ci --ignore-scripts
npm --prefix dashboard run build
```

On this Windows machine with an RTX 2070 (8 GiB), acquire the official quantized
7B model and portable GPU runtime (about 5.4 GB total). SHA-256 verification is
mandatory. This explicit command downloads assets; inference stays on loopback:

```powershell
uv run python -m training.acquire_gguf
./deploy/start-local.ps1
```

Existing downloaded artifacts are verified before reuse. Once the model
exists, skip acquisition on later starts. The launcher generates a private local
inference API key in the ignored artifacts directory and starts hidden processes.
Do not expose or commit that key. Open http://127.0.0.1:8000 and use the
explicit sample demo key from .env.mvp.example. This serves the built console and
API on one origin. The separate Vite development console on port 5173 also works.

The default is Qwen2.5-7B-Instruct Q4_K_M, not the earlier 1.5B CPU model.
The runtime uses a 4096-token context, one inference slot and bounded responses.
Other hardware needs its own measured model/runtime configuration. The launcher
refuses occupied ports; service logs are in artifacts/local-inference.

In **Agent Evaluation**, choose a normal-task email or natural-language attack. Run one
configuration or the adaptive comparison. The page polls status, shows each
model response, action, tool observation, policy trace and oracle outcome,
and exports JSON evidence. Jobs survive restart; unfinished inference is marked
interrupted, never silently resumed or reported completed.

## Evidence and budgets

Each comparison runs five configurations, a normal-task case, a supplied static
attack, and up to three adaptive attacker revisions per configuration. Default
is one revision. Six target turns per run (maximum eight), 128 total model calls,
600-second campaign timeout, one executing job, two active jobs per tenant,
eight globally, and 200 retained jobs per tenant. A full queue returns 429.
These caps are intentional MVP limits; export evidence and archive the database
before starting a fresh evaluation store. Model names and endpoints are server
configuration. Clients cannot supply credentials, paths or provider URLs.

POST /lab/jobs requires Idempotency-Key (8-128 safe characters). Reusing a key
with the same body returns the existing job; a different body returns 409.
GET /lab/jobs and GET /lab/jobs/{id} are tenant-scoped. Operators/admins can POST
/lab/jobs/{id}/cancel. Cancellation prevents publishing a late result. A local
CPU generation already in progress may finish its bounded generation before
the worker is reusable; this is not hard process isolation.

An invalid model schema, timeout, exhausted turn budget or attacker generation
failure is **inconclusive**, not a successful defense. Utility checks the requested
Tuesday/10:00 answer and absence of extra email effects. ASR is an observed-effect
metric with explicit invalid-run counts, not a guarantee. This small scenario
does not replace held-out benchmark evaluation or broad utility measurements.

The raw job store intentionally contains only sample-data email/model transcripts.
The general audit stores metadata and labeled trace snapshots, not raw prompts.
Never send real customer data to the research runner.

## Operations before deployment

- Set MECHA_ENV=production, persistent audit/control paths, explicit
  MECHA_ALLOWED_HOSTS, and tenant keys of at least 32 random characters. Demo
  credentials and ephemeral state are rejected. Store keys outside Git.
- Bind only to an internal interface behind a trusted TLS reverse proxy.
  Authentication is mandatory; no permissive CORS or provider URL from clients.
- Run exactly one worker/replica. Production startup takes an OS-released exclusive
  worker lock for the state database. Postgres and distributed execution are not
  implemented. SQLite transactions cover one host, not cross-host replication.
- /health is liveness; /ready checks database connections. Neither asserts model
  quality, completed weight loading, disk capacity or passing release gates.
- Back up BOTH control and audit files using deploy/backup.py. The control file
  includes policy revisions, grants, jobs and sample arena submissions. Stop the
  worker before restore; preserve external signed audit anchors separately.
- Environment-seeded tenant credentials override stored values on restart.
  Rotate seeded keys through the secret configuration and restart. No SSO,
  user session management or delegated multi-user approval UI is certified.
- Audit and job database access requires filesystem permissions for the service
  identity. The software does not provide database-at-rest encryption.

## Production release gates still open

1. Representative valid real-model campaigns and held-out normal-task utility across
   natural email/RAG/browser tasks. The current MVP only implements email.
2. Durable network p95 <50 ms at the agreed concurrency. The Windows concurrency
   16 run failed; in-process and concurrency-four localhost measurements pass.
3. Linux container/Helm/isolation deployment checks, restore rehearsal, host
   resource limits and malicious-output stress. Local-only verification cannot
   certify these. Firecracker is not implemented.
4. Independent security review, live provider/MCP interoperability, hosted CI,
   signed release evidence and owner-approved release/legal/disclosure details.

Do not turn this list into checked boxes because source files or scripts exist.

CPU inference uses explicit float32. The checkpoint's bfloat16 dtype was too
slow on this CPU, and dynamic int8 was not retained after backend failures;
see ADR-0008. Each generation permits at most 192 new tokens and 60 seconds,
within the campaign budget. Standalone CLI runs save incremental
.checkpoint.json evidence.
