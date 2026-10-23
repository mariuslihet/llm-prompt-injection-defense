"""Minimal async Python SDK. Tool execution stays on the trusted server."""

from collections.abc import AsyncIterator

import httpx


class Mecha:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30,
            follow_redirects=False,
        )

    async def close(self) -> None:
        await self.client.aclose()

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
