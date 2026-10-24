"""Minimal async Python SDK. Tool execution stays on the trusted server."""

import uuid
from collections.abc import AsyncIterator

import httpx


class Mecha:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30,
            follow_redirects=False,
            trust_env=False,
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def start_agent(
        self,
        email: str,
        defense: str = "full-ifc",
        *,
        campaign: bool = False,
        idempotency_key: str | None = None,
    ) -> dict[str, object]:
        """Start a bounded fake-email job; never grants authority over real tools."""
        response = await self.client.post(
            "/lab/jobs",
            headers={"Idempotency-Key": idempotency_key or uuid.uuid4().hex},
            json={"kind": "campaign" if campaign else "agent", "email": email, "defense": defense},
        )
        response.raise_for_status()
        return response.json()

    async def job(self, identity: str) -> dict[str, object]:
        if not identity.isalnum() or len(identity) != 32:
            raise ValueError("invalid job ID")
        response = await self.client.get("/lab/jobs/" + identity)
        response.raise_for_status()
        return response.json()

    async def cancel_job(self, identity: str) -> dict[str, object]:
        if not identity.isalnum() or len(identity) != 32:
            raise ValueError("invalid job ID")
        response = await self.client.post("/lab/jobs/" + identity + "/cancel")
        response.raise_for_status()
        return response.json()

    async def complete(self, content: str, model: str = "mecha-mock") -> str:
        response = await self.client.post(
            "/v1/chat/completions",
            json={"model": model, "messages": [{"role": "user", "content": content}]},
        )
        response.raise_for_status()
        return str(response.json()["choices"][0]["message"]["content"])

    async def stream(self, content: str) -> AsyncIterator[str]:
        async with self.client.stream(
            "POST",
            "/v1/chat/completions",
            json={"stream": True, "messages": [{"role": "user", "content": content}]},
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    yield line[6:]
