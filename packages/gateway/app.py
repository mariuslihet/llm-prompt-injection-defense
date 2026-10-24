"""Mock-first gateway. Run on loopback; explicit credentials required to serve requests."""

import asyncio
import json
import os
import re
import sqlite3
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

import yaml
from anyio import to_thread
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from packages.core import Segment
from packages.detectors import LocalClassifier
from packages.detectors.cascade import Cascade, CascadeConfig, ProviderJudge
from packages.gateway.providers import Provider, configured_provider
from packages.ifc import Interpreter, Program, plan, trusted_value, untrusted_value
from packages.policy import binding, compile_policy, verify
from packages.policy.store import PolicyStore
from packages.sanitizers import sanitize
from packages.storage import Identity, State, StateApprovals
from packages.telemetry import Audit

DEFAULT_POLICY = Path(__file__).parents[1] / "policy" / "default.yaml"


class ServerTiming:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        started = time.perf_counter()

        async def timed_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                duration = (time.perf_counter() - started) * 1000
                headers.append((b"server-timing", f"mecha;dur={duration:.3f}".encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, timed_send)


class SecurityHeaders:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"].startswith("/api/"):
            scope = {**scope, "path": scope["path"][4:], "raw_path": scope["raw_path"][4:]}

        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"cache-control", b"no-store"),
                        (b"content-security-policy", b"frame-ancestors 'none'"),
                    ]
                )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, secure_send)


class BodyLimit:
    def __init__(self, app: ASGIApp, timeout_seconds: float = 10) -> None:
        self.app = app
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        body = bytearray()
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                message = await asyncio.wait_for(receive(), max(0, deadline - time.monotonic()))
            except TimeoutError:
                await JSONResponse({"detail": "request body timeout"}, status_code=408)(
                    scope, receive, send
                )
                return
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 131072:
                await JSONResponse({"detail": "request too large"}, status_code=413)(
                    scope, receive, send
                )
                return
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


class Tenant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    key: str = Field(min_length=16)
    role: Literal["viewer", "operator", "admin"]
    platform_admin: bool = False


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["user", "assistant", "tool", "system"]
    content: str = Field(max_length=32768)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(default="mecha-mock", min_length=1, max_length=128)
    messages: list[ChatMessage] = Field(min_length=1, max_length=32)
    stream: bool = False
    max_tokens: int = Field(default=1024, ge=1, le=4096)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: Literal["send_email", "fetch_url"]
    arguments: dict[str, str]


class ToolRequest(ApprovalRequest):
    approval: str = ""
    untrusted_context: str = Field(default="", max_length=32768)


class PolicyEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(max_length=65536)
    dry_run: bool = True


class Revision(BaseModel):
    revision: int = Field(ge=1)


class TenantEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    role: Literal["viewer", "operator", "admin"]


class IFCRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task: Literal["summarize", "email-summary"] = "summarize"
    document: str = Field(max_length=32768)
    recipient: str = Field(default="team@example.invalid", max_length=254)


class RPC(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jsonrpc: Literal["2.0"] = "2.0"
    id: int | str
    method: str = Field(max_length=100)
    params: dict[str, object] = Field(default_factory=dict)


def create_app(
    *,
    tenants: dict[str, Tenant] | None = None,
    provider: Provider | None = None,
    audit: Audit | None = None,
    rate_limit: int = 60,
    request_hook: Callable[[str], str] | None = None,
    response_hook: Callable[[str], str] | None = None,
    cascade: Cascade | None = None,
    state_path: str | None = None,
    agent_provider: Provider | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        try:
            yield
        finally:
            await jobs.close()
            if worker_lock:
                worker_lock.close()
            if audit is None:
                ledger.close()
            state.close()
            store.db.close()
            arena.db.close()

    api = FastAPI(title="Mecha", version="0.1.0", lifespan=lifespan)
    api.add_middleware(BodyLimit)
    api.add_middleware(ServerTiming)
    api.add_middleware(SecurityHeaders)
    if os.getenv("MECHA_OTEL_ENDPOINT"):
        if os.getenv("MECHA_ALLOW_TELEMETRY") != "1":
            raise ValueError("telemetry export requires explicit opt-in")
        from packages.telemetry.otel import configure

        configure(os.environ["MECHA_OTEL_ENDPOINT"])
    configured = (
        tenants
        if tenants is not None
        else {
            k: Tenant.model_validate(v)
            for k, v in json.loads(os.getenv("MECHA_TENANT_KEYS", "{}")).items()
        }
    )
    model_provider = provider or configured_provider(os.getenv("MECHA_PROVIDER", "mock"))
    ledger = audit or Audit(os.getenv("MECHA_AUDIT_PATH", ":memory:"))
    policy = compile_policy(DEFAULT_POLICY.read_text(encoding="utf-8"))
    if verify(policy):
        raise ValueError("unsafe gateway policy")
    database = state_path if state_path is not None else os.getenv("MECHA_STATE_PATH", ":memory:")
    worker_lock = None
    if os.getenv("MECHA_ENV") == "production":
        if database == ":memory:" or os.getenv("MECHA_AUDIT_PATH", ":memory:") == ":memory:":
            raise ValueError("production requires durable audit and control storage")
        if not configured or any(
            len(t.key) < 32 or "fake" in t.key.lower() for t in configured.values()
        ):
            raise ValueError(
                "production requires non-demo tenant credentials of at least 32 characters"
            )
        hosts = os.getenv("MECHA_ALLOWED_HOSTS", "").split(",")
        if not hosts or any(not h.strip() or "*" in h for h in hosts):
            raise ValueError("production requires explicit allowed hosts")
        from starlette.middleware.trustedhost import TrustedHostMiddleware

        api.add_middleware(TrustedHostMiddleware, allowed_hosts=[h.strip() for h in hosts])
        from packages.worker_lock import WorkerLock

        worker_lock = WorkerLock(database)
    state = State(database)
    for name, tenant_config in configured.items():
        state.seed(
            name,
            tenant_config.key,
            Identity(role=tenant_config.role, platform_admin=tenant_config.platform_admin),
        )
    approvals = StateApprovals(state)
    detector = cascade or Cascade(
        CascadeConfig(
            mode=os.getenv("MECHA_DETECTOR_MODE", "block"),
            threshold=float(os.getenv("MECHA_DETECTOR_THRESHOLD", "0.6")),
        ),
        classifier=LocalClassifier(os.environ["MECHA_CLASSIFIER_PATH"])
        if os.getenv("MECHA_CLASSIFIER_PATH")
        else None,
        judge=ProviderJudge(model_provider, os.environ["MECHA_JUDGE_MODEL"])
        if os.getenv("MECHA_JUDGE_MODEL")
        else None,
    )
    store = PolicyStore(DEFAULT_POLICY.read_text(encoding="utf-8"), database)
    from lab.arena import Arena

    arena = Arena(database)
    from lab.campaigns import RunSpec, execute
    from packages.jobs import JobCapacity, JobConflict, Jobs

    jobs = Jobs(database)
    lab_kind = os.getenv("MECHA_AGENT_PROVIDER", "disabled")
    lab_provider = agent_provider or (
        configured_provider(lab_kind) if lab_kind != "disabled" else None
    )
    lab_model = os.getenv("MECHA_AGENT_MODEL", "local-operator-selected")
    api.state.audit = ledger
    api.state.policy = policy
    api.state.control = state
    api.state.jobs = jobs

    async def authenticate(request: Request) -> tuple[str, Identity]:
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ")
        supplied = supplied or request.headers.get("x-api-key", "")

        def lookup():
            match = state.authenticate(supplied)
            return match, state.allow_request(match[0], rate_limit) if match else False

        match, admitted = await to_thread.run_sync(lookup) if state.persistent else lookup()
        if match is None:
            raise HTTPException(401, "invalid API key")
        if not admitted:
            raise HTTPException(429, "tenant rate limit")
        return match

    Auth = Annotated[tuple[str, Identity], Depends(authenticate)]

    async def append_decision(tenant: str, event: dict[str, str | int | float | bool]) -> str:
        if ledger.persistent:
            return await to_thread.run_sync(ledger.append, tenant, event)
        return ledger.append(tenant, event)

    def require(auth: tuple[str, Identity], roles: set[str]) -> str:
        if auth[1].role not in roles:
            raise HTTPException(403, "role denied")
        return auth[0]

    @api.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "provider": type(model_provider).__name__}

    @api.get("/ready")
    async def ready():
        try:
            with state.lock:
                state.db.execute("SELECT 1").fetchone()
            with ledger.lock:
                ledger.db.execute("SELECT 1").fetchone()
            return {"status": "ready", "storage": "sqlite", "worker_mode": "single"}
        except sqlite3.Error as exc:
            raise HTTPException(503, "storage unavailable") from exc

    @api.get("/lab/config")
    async def lab_config(auth: Auth):
        require(auth, {"viewer", "operator", "admin"})
        from agents.email import ATTACK_EMAIL, BENIGN_EMAIL, DEFENSES, TASK

        return {
            "enabled": lab_provider is not None,
            "provider": type(lab_provider).__name__ if lab_provider else "disabled",
            "model": lab_model,
            "defenses": DEFENSES,
            "task": TASK,
            "attack_email": ATTACK_EMAIL,
            "benign_email": BENIGN_EMAIL,
            "tools": "fake inbox, fake private memo, simulated email ledger",
        }

    @api.post("/lab/jobs", status_code=202)
    async def submit_job(body: RunSpec, request: Request, auth: Auth):
        tenant = require(auth, {"operator", "admin"})
        if lab_provider is None:
            raise HTTPException(503, "configure MECHA_AGENT_PROVIDER on the server first")
        key = request.headers.get("idempotency-key", "")
        if not re.fullmatch(r"[a-zA-Z0-9_-]{8,128}", key):
            raise HTTPException(422, "Idempotency-Key header required (8-128 safe characters)")
        try:
            identity, created = jobs.create(tenant, body, key)
        except JobConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except JobCapacity as exc:
            raise HTTPException(429, str(exc)) from exc
        if created:
            snapshot = store.get(tenant)

            async def work(progress):
                result = await execute(body, lab_provider, lab_model, snapshot, tenant, progress)
                await append_decision(
                    tenant,
                    {
                        "action": "allow",
                        "rule": "lab-job-complete",
                        "request_id": identity,
                        "count": result["model_calls"],
                    },
                )
                return result

            try:
                await append_decision(
                    tenant, {"action": "allow", "rule": "lab-job-created", "request_id": identity}
                )
            except Exception as exc:
                jobs.update(tenant, identity, "failed", {"error_code": "audit_unavailable"})
                raise HTTPException(503, "audit unavailable") from exc
            jobs.launch(tenant, identity, work)
        return jobs.get(tenant, identity)

    @api.get("/lab/jobs")
    async def list_jobs(auth: Auth):
        return {"jobs": jobs.list(auth[0])}

    @api.get("/lab/jobs/{identity}")
    async def get_job(identity: str, auth: Auth):
        try:
            return jobs.get(auth[0], identity)
        except KeyError as exc:
            raise HTTPException(404, "job not found") from exc

    @api.post("/lab/jobs/{identity}/cancel")
    async def cancel_job(identity: str, auth: Auth):
        tenant = require(auth, {"operator", "admin"})
        try:
            return jobs.cancel(tenant, identity)
        except KeyError as exc:
            raise HTTPException(404, "job not found") from exc

    async def completion(body: ChatRequest, auth: tuple[str, Identity]) -> tuple[str, str]:
        tenant = require(auth, {"operator", "admin"})
        started = time.perf_counter()
        request_id = str(uuid.uuid4())
        # Clients cannot inject system authority. Gateway owns its system prompt.
        if any(m.role == "system" for m in body.messages):
            raise HTTPException(422, "system messages require a trusted server adapter")
        messages = []
        for message in body.messages:
            text = request_hook(message.content) if request_hook else message.content
            detection = await detector.inspect(text)
            if detection.action in {"flag", "shadow"}:
                await append_decision(
                    tenant,
                    {
                        "action": detection.action,
                        "rule": "detector-cascade",
                        "reason": ",".join(detection.reasons),
                        "request_id": request_id,
                    },
                )
            if detection.action == "block":
                await append_decision(
                    tenant,
                    {
                        "action": "block",
                        "rule": "heuristics",
                        "reason": ",".join(detection.reasons),
                        "request_id": request_id,
                    },
                )
                raise HTTPException(403, "prompt flagged by heuristics")
            segment = Segment(
                kind="user" if message.role == "user" else "tool",
                provenance=f"tenant:{tenant}",
                value=untrusted_value(text),
            )
            messages.append({"role": "user", "content": segment.spotlight()})
        try:
            output = await model_provider.complete(messages, body.model)
        except Exception as exc:
            raise HTTPException(502, "provider failed closed") from exc
        if response_hook:
            output = response_hook(output)
        cleaned = sanitize(output)
        await append_decision(
            tenant,
            {
                "action": "allow",
                "rule": "output-sanitizer",
                "reason": ",".join(cleaned.findings),
                "request_id": request_id,
                "duration_ms": (time.perf_counter() - started) * 1000,
            },
        )
        return cleaned.text, request_id

    @api.post("/v1/chat/completions", response_model=None)
    async def chat(body: ChatRequest, auth: Auth):
        text, request_id = await completion(body, auth)
        if body.stream:

            async def chunks() -> AsyncIterator[str]:
                for offset in range(0, len(text), 64):
                    chunk = {
                        "id": request_id,
                        "object": "chat.completion.chunk",
                        "model": body.model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": text[offset : offset + 64]},
                                "finish_reason": None,
                            }
                        ],
                    }
                    yield "data: " + json.dumps(chunk) + "\n\n"
                yield (
                    "data: "
                    + json.dumps(
                        {
                            "id": request_id,
                            "object": "chat.completion.chunk",
                            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                        }
                    )
                    + "\n\n"
                )
                yield "data: [DONE]\n\n"

            return StreamingResponse(chunks(), media_type="text/event-stream")
        return {
            "id": request_id,
            "object": "chat.completion",
            "model": body.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    @api.post("/v1/messages")
    async def anthropic(body: ChatRequest, auth: Auth):
        text, request_id = await completion(body, auth)
        if body.stream:

            async def events() -> AsyncIterator[str]:
                events = [
                    (
                        "message_start",
                        {
                            "type": "message_start",
                            "message": {
                                "id": request_id,
                                "type": "message",
                                "role": "assistant",
                                "model": body.model,
                                "content": [],
                                "usage": {"input_tokens": 0, "output_tokens": 0},
                            },
                        },
                    ),
                    (
                        "content_block_start",
                        {
                            "type": "content_block_start",
                            "index": 0,
                            "content_block": {"type": "text", "text": ""},
                        },
                    ),
                    (
                        "content_block_delta",
                        {
                            "type": "content_block_delta",
                            "index": 0,
                            "delta": {"type": "text_delta", "text": text},
                        },
                    ),
                    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                    (
                        "message_delta",
                        {
                            "type": "message_delta",
                            "delta": {"stop_reason": "end_turn"},
                            "usage": {"output_tokens": 0},
                        },
                    ),
                    ("message_stop", {"type": "message_stop"}),
                ]
                for name, data in events:
                    yield f"event: {name}\ndata: {json.dumps(data)}\n\n"

            return StreamingResponse(events(), media_type="text/event-stream")
        return {
            "id": request_id,
            "type": "message",
            "role": "assistant",
            "model": body.model,
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }

    def tool_values(body: ApprovalRequest):
        # This adapter accepts arguments from the authenticated operator as
        # explicit intent; model-derived inputs use the interpreter's value refs.
        return {
            k: trusted_value(v, sinks=frozenset({body.tool})) for k, v in body.arguments.items()
        }

    @api.post("/approvals")
    async def approve(body: ApprovalRequest, auth: Auth):
        tenant = require(auth, {"admin"})
        token = approvals.issue(binding(tenant, store.get(tenant), body.tool, tool_values(body)))
        ledger.append(tenant, {"action": "approve", "rule": body.tool, "reason": "human API"})
        return {"approval": token, "expires_in": 300}

    @api.post("/tools/call")
    async def tool_call(body: ToolRequest, auth: Auth):
        tenant = require(auth, {"operator", "admin"})
        values = tool_values(body)
        if body.untrusted_context:
            values["_context"] = untrusted_value(body.untrusted_context)
        program = Program.model_validate(
            {
                "instructions": [
                    {
                        "op": "call",
                        "tool": body.tool,
                        "arguments": {k: k for k in body.arguments},
                        "approval": body.approval,
                    }
                ]
            }
        )
        runtime = Interpreter(store.get(tenant), tenant, approvals)
        runtime.run(program, values)
        decision = runtime.decisions[-1]
        ledger.append(
            tenant,
            {
                "action": "allow" if decision.allowed else "block",
                "rule": decision.rule,
                "reason": decision.reason,
                "trace": runtime.snapshot().model_dump_json(),
            },
        )
        return {"decision": decision.model_dump(), "effects": runtime.effects, "simulated": True}

    @api.post("/ifc/run")
    async def ifc_run(body: IFCRun, auth: Auth):
        tenant = require(auth, {"operator", "admin"})
        runtime = Interpreter(store.get(tenant), tenant, approvals)
        values = runtime.run(
            plan(body.task),
            {
                "document": untrusted_value(body.document),
                "recipient": trusted_value(body.recipient, sinks=frozenset({"send_email"})),
            },
        )
        denied = any(not decision.allowed for decision in runtime.decisions)
        digest = ledger.append(
            tenant,
            {
                "action": "block" if denied else "allow",
                "rule": "ifc",
                "reason": "restricted program execution",
                "trace": runtime.snapshot().model_dump_json(),
            },
        )
        return {
            "summary": sanitize(values["summary"].data).text,
            "incident": digest,
            "trace": runtime.snapshot().model_dump(mode="json"),
            "simulated": True,
        }

    @api.get("/incidents/{digest}")
    async def incident_get(digest: str, auth: Auth):
        result = ledger.incident(auth[0], digest)
        if result is None:
            raise HTTPException(404, "unknown tenant incident")
        return result

    @api.get("/metrics")
    async def metrics_get(auth: Auth):
        return ledger.metrics(auth[0])

    @api.get("/audit")
    async def audit_events(auth: Auth):
        tenant = require(auth, {"viewer", "operator", "admin"})
        return {"events": ledger.events(tenant), "chain_valid": ledger.verify()}

    @api.get("/policy")
    async def policy_get(auth: Auth):
        tenant = require(auth, {"viewer", "operator", "admin"})
        current = store.get(tenant)
        return {
            "policy": current.model_dump(mode="json"),
            "digest": current.digest,
            "text": store.text(tenant),
            "history": store.history(tenant),
        }

    @api.post("/policy/stage")
    async def policy_stage(body: PolicyEdit, auth: Auth):
        tenant = require(auth, {"admin"})
        try:
            parsed = compile_policy(body.text)
            errors = verify(parsed)
            if errors:
                return {"valid": False, "errors": errors}
            if body.dry_run:
                return {"valid": True, "digest": parsed.digest}
            revision = store.stage(tenant, body.text)
        except (ValueError, TypeError, yaml.YAMLError) as exc:
            raise HTTPException(422, "invalid policy") from exc
        ledger.append(tenant, {"action": "stage", "rule": "policy", "reason": str(revision)})
        return {"valid": True, "revision": revision, "digest": parsed.digest}

    @api.post("/policy/promote")
    async def policy_promote(body: Revision, auth: Auth):
        tenant = require(auth, {"admin"})
        try:
            store.promote(tenant, body.revision)
        except ValueError as exc:
            raise HTTPException(404, "unknown revision") from exc
        ledger.append(tenant, {"action": "promote", "rule": "policy", "reason": str(body.revision)})
        return {"digest": store.get(tenant).digest}

    @api.get("/tenants")
    async def tenant_list(auth: Auth):
        require(auth, {"admin"})
        if not auth[1].platform_admin:
            raise HTTPException(403, "platform administrator required")
        return state.tenants()

    @api.post("/tenants")
    async def tenant_create(body: TenantEdit, auth: Auth):
        tenant = require(auth, {"admin"})
        if not auth[1].platform_admin:
            raise HTTPException(403, "platform administrator required")
        try:
            key = state.create_tenant(body.name, body.role)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "tenant already exists") from exc
        ledger.append(
            tenant, {"action": "create-tenant", "rule": "tenant", "reason": "platform admin"}
        )
        return {
            "name": body.name,
            "key": key,
            "warning": "Save once; only the key hash is retained",
        }

    @api.get("/arena/levels")
    async def arena_levels(auth: Auth):
        require(auth, {"viewer", "operator", "admin"})
        from lab.arena import LEVELS

        return {
            "levels": list(LEVELS),
            "attacks": [a.model_dump(by_alias=True) for a in arena.attacks.values()],
        }

    @api.post("/arena/submit")
    async def arena_submit(request: Request, auth: Auth):
        from pydantic import ValidationError

        from lab.arena import Submission

        tenant = require(auth, {"operator", "admin"})
        try:
            return arena.submit(tenant, Submission.model_validate(await request.json()))
        except (ValueError, ValidationError) as exc:
            raise HTTPException(422, "invalid sandbox fixture submission") from exc

    @api.get("/arena/leaderboard")
    async def arena_leaderboard(auth: Auth):
        return arena.leaderboard(auth[0])

    @api.post("/arena/review/{digest}")
    async def arena_review(digest: str, auth: Auth):
        tenant = require(auth, {"admin"})
        try:
            arena.review(tenant, digest)
        except KeyError as exc:
            raise HTTPException(404, "unknown submission") from exc
        ledger.append(
            tenant, {"action": "review", "rule": "arena", "reason": "corpus candidate accepted"}
        )
        return {"accepted": True}

    @api.get("/arena/reviewed")
    async def arena_reviewed(auth: Auth):
        tenant = require(auth, {"admin"})
        return {"candidates": arena.candidates(tenant)}

    @api.get("/arena/pending")
    async def arena_pending(auth: Auth):
        return {"candidates": arena.candidates(require(auth, {"admin"}), "pending")}

    @api.get("/export/cef")
    async def export_cef(auth: Auth):
        from packages.telemetry.export import cef

        return {"events": [cef(item["event"]) for item in ledger.events(auth[0])]}

    @api.post("/mcp")
    async def mcp(body: RPC, auth: Auth):
        tenant = require(auth, {"operator", "admin"})
        if body.method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mecha-mock", "version": "0.1.0"},
            }
        elif body.method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "mock_summarize",
                        "description": "Return fake-data text only.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                            "required": ["text"],
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        elif body.method == "tools/call":
            params = body.params
            from packages.detectors.channels import honeytool

            alert = honeytool(str(params.get("name", "")))
            if alert["severity"] == "high":
                ledger.append(
                    tenant,
                    {
                        "action": "block",
                        "rule": alert["rule"],
                        "reason": "decoy tool touched",
                        "severity": "high",
                    },
                )
            arguments = params.get("arguments")
            if (
                params.get("name") != "mock_summarize"
                or not isinstance(arguments, dict)
                or set(arguments) != {"text"}
                or not isinstance(arguments["text"], str)
                or len(arguments["text"]) > 32768
            ):
                return {
                    "jsonrpc": "2.0",
                    "id": body.id,
                    "error": {"code": -32602, "message": "tool/arguments denied"},
                }
            cleaned = sanitize(arguments["text"])
            ledger.append(
                tenant, {"action": "allow", "rule": "mock-mcp", "reason": "no external tools"}
            )
            result = {
                "content": [{"type": "text", "text": cleaned.text}],
                "isError": False,
                "_meta": {"trust": "untrusted", "source": "mock-mcp"},
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": body.id,
                "error": {"code": -32601, "message": "unsupported method"},
            }
        return {"jsonrpc": "2.0", "id": body.id, "result": result}

    if os.getenv("MECHA_DASHBOARD_PATH"):
        from fastapi.staticfiles import StaticFiles

        api.mount(
            "/",
            StaticFiles(directory=os.environ["MECHA_DASHBOARD_PATH"], html=True),
            name="console",
        )
    return api


app = create_app()
