"""Explicitly opt-in providers. Tests use MockProvider and no network."""

import os
from typing import Protocol

import httpx


class Provider(Protocol):
    async def complete(self, messages: list[dict[str, str]], model: str) -> str: ...


class MockProvider:
    async def complete(self, messages: list[dict[str, str]], model: str) -> str:
        return "Mock response: " + messages[-1]["content"][:4096]


class RealProvider:
    def __init__(self, kind: str) -> None:
        if os.getenv("MECHA_ALLOW_NETWORK") != "1":
            raise ValueError("network provider requires MECHA_ALLOW_NETWORK=1")
        self.kind = kind
        if kind == "openai":
            self.url, self.key = (
                "https://api.openai.com/v1/chat/completions",
                os.environ["OPENAI_API_KEY"],
            )
        elif kind == "anthropic":
            self.url, self.key = (
                "https://api.anthropic.com/v1/messages",
                os.environ["ANTHROPIC_API_KEY"],
            )
        elif kind in {"ollama", "vllm"}:
            self.url = (
                os.getenv("MECHA_LOCAL_URL", "http://127.0.0.1:11434/v1").rstrip("/")
                + "/chat/completions"
            )
            self.key = os.getenv("MECHA_LOCAL_KEY", "local")
        else:
            raise ValueError("unknown provider")

    async def complete(self, messages: list[dict[str, str]], model: str) -> str:
        headers = {"Authorization": f"Bearer {self.key}"}
        payload: dict[str, object] = {"model": model, "messages": messages, "stream": False}
        if self.kind == "anthropic":
            headers = {"x-api-key": self.key, "anthropic-version": "2023-06-01"}
            payload["max_tokens"] = 1024
        async with httpx.AsyncClient(timeout=30, follow_redirects=False, trust_env=False) as client:
            response = await client.post(self.url, json=payload, headers=headers)
            response.raise_for_status()
            if len(response.content) > 1_000_000:
                raise ValueError("provider response too large")
            data = response.json()
        if self.kind == "anthropic":
            return str(data["content"][0]["text"])
        return str(data["choices"][0]["message"]["content"])
