"""Opt-in HTTP JSON-RPC MCP transport with pins, policy and quarantined results."""

import asyncio
import os
from urllib.parse import urlsplit

import httpx

from packages.core import Confidentiality, Label, Trust, Value
from packages.gateway.mcp import Catalog, ToolDefinition
from packages.policy import Policy, evaluate


class MCPProxy:
    def __init__(
        self,
        server: str,
        endpoint: str,
        catalog: Catalog,
        policy: Policy,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.username
            or parsed.password
            or parsed.hostname is None
            or parsed.fragment
            or parsed.query
        ):
            raise ValueError("trusted MCP endpoint configuration required")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("plaintext MCP is loopback-only")
        self.server, self.endpoint, self.catalog, self.policy = server, endpoint, catalog, policy
        self._next_id = 0
        self._initialized = False
        self._initializing = asyncio.Lock()
        self._session: str | None = None
        if transport is None and os.getenv("MECHA_ALLOW_NETWORK") != "1":
            raise ValueError("MCP network transport requires explicit opt-in")
        self.client = httpx.AsyncClient(
            transport=transport, timeout=10, follow_redirects=False, trust_env=False
        )

    async def _rpc(self, method: str, params: dict[str, object]) -> dict[str, object]:
        self._next_id += 1
        request_id = self._next_id
        async with self.client.stream(
            "POST",
            self.endpoint,
            json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            headers={"mcp-session-id": self._session} if self._session else {},
        ) as response:
            response.raise_for_status()
            session = response.headers.get("mcp-session-id")
            if session is not None:
                if len(session) > 128 or not session.isascii() or any(ord(c) < 33 for c in session):
                    raise ValueError("invalid MCP session identifier")
                self._session = session
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > 131072:
                    raise ValueError("MCP response too large")
        import json

        if bytes(body).lstrip().startswith(b"event:") or bytes(body).lstrip().startswith(b"data:"):
            values = [
                json.loads(line[5:].strip())
                for line in body.decode().splitlines()
                if line.startswith("data:")
            ]
            value = next(
                (
                    value
                    for value in values
                    if isinstance(value, dict) and value.get("id") == request_id
                ),
                None,
            )
        else:
            value = json.loads(body)
        if (
            not isinstance(value, dict)
            or value.get("jsonrpc") != "2.0"
            or value.get("id") != request_id
            or "error" in value
            or not isinstance(value.get("result"), dict)
        ):
            raise ValueError("invalid MCP response")
        return value["result"]

    async def initialize(self) -> None:
        async with self._initializing:
            if self._initialized:
                return
            result = await self._rpc(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mecha", "version": "0.1.0"},
                },
            )
            if result.get("protocolVersion") != "2024-11-05":
                raise ValueError("unsupported MCP protocol version")
            async with self.client.stream(
                "POST",
                self.endpoint,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers={"mcp-session-id": self._session} if self._session else {},
            ) as response:
                response.raise_for_status()
            self._initialized = True

    async def discover(self) -> tuple[str, ...]:
        await self.initialize()
        result = await self._rpc("tools/list", {})
        tools = result.get("tools")
        if not isinstance(tools, list) or len(tools) > 64:
            raise ValueError("invalid MCP tool catalog")
        registered = []
        for tool in tools:
            if not isinstance(tool, dict):
                raise ValueError("invalid MCP definition")
            definition = ToolDefinition(
                server=self.server,
                name=tool["name"],
                description=tool.get("description", ""),
                input_schema=tool["inputSchema"],
            )
            registered.append(self.catalog.register(definition, str(tool.get("signature", ""))))
        return tuple(registered)

    async def call(
        self,
        tool: str,
        arguments: dict[str, Value],
        *,
        read_untrusted: bool,
        approved: bool = False,
    ) -> Value:
        decision = evaluate(
            self.policy, tool, arguments, read_untrusted=read_untrusted, approved=approved
        )
        if not decision.allowed:
            raise PermissionError("MCP policy denied")
        # Recheck every tool definition before a call to detect a post-discovery rug pull.
        current = await self.discover()
        if f"{self.server}/{tool}" not in current:
            raise PermissionError("tool absent from current scoped MCP catalog")
        result = await self._rpc(
            "tools/call",
            {"name": tool, "arguments": {name: value.data for name, value in arguments.items()}},
        )
        if result.get("isError"):
            raise ValueError("MCP tool reported an error")
        content = result.get("content")
        if not isinstance(content, list):
            raise ValueError("invalid MCP result content")
        texts = []
        for block in content:
            if (
                not isinstance(block, dict)
                or block.get("type") != "text"
                or not isinstance(block.get("text"), str)
            ):
                raise ValueError("unsupported MCP result block")
            texts.append(block["text"])
        return Value(
            data="\n".join(texts),
            label=Label(
                sources=frozenset({f"mcp:{self.server}"}),
                trust=Trust.UNTRUSTED,
                confidentiality=Confidentiality.PRIVATE,
            ),
        )

    async def close(self) -> None:
        await self.client.aclose()
