"""Explicitly opt-in providers. Tests use MockProvider and no network."""

import json
import os
import threading
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

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
        elif kind in {"ollama", "vllm", "llamacpp"}:
            self.url = (
                os.getenv("MECHA_LOCAL_URL", "http://127.0.0.1:11434/v1").rstrip("/")
                + "/chat/completions"
            )
            self.key = os.getenv("MECHA_LOCAL_KEY", "local")
        else:
            raise ValueError("unknown provider")
        endpoint = urlsplit(self.url)
        if (
            endpoint.scheme not in {"http", "https"}
            or not endpoint.hostname
            or endpoint.username
            or endpoint.password
            or endpoint.query
            or endpoint.fragment
        ):
            raise ValueError("invalid operator-configured provider endpoint")
        if kind == "llamacpp" and endpoint.hostname not in {"127.0.0.1", "::1"}:
            raise ValueError("llamacpp requires a literal loopback endpoint")

    async def complete(self, messages: list[dict[str, str]], model: str) -> str:
        headers = {"Authorization": f"Bearer {self.key}"}
        payload: dict[str, object] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "max_tokens": 512,
        }
        payload["temperature"] = 0
        if self.kind == "llamacpp":
            payload["seed"] = 42
        if self.kind == "anthropic":
            headers = {"x-api-key": self.key, "anthropic-version": "2023-06-01"}
            payload["system"] = "\n".join(m["content"] for m in messages if m["role"] == "system")
            payload["messages"] = [m for m in messages if m["role"] != "system"]
        async with httpx.AsyncClient(
            timeout=120 if self.kind == "llamacpp" else 30,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            body = bytearray()
            async with client.stream("POST", self.url, json=payload, headers=headers) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 1_000_000:
                        raise ValueError("provider response too large")
            data = json.loads(body)
        text = (
            data["content"][0]["text"]
            if self.kind == "anthropic"
            else data["choices"][0]["message"]["content"]
        )
        if not isinstance(text, str) or len(text) > 32768:
            raise ValueError("invalid provider text response")
        return text


class LocalHFProvider:
    """Operator-selected local weights only. No tools, downloads or remote code."""

    def __init__(self, directory: str) -> None:
        self.directory = str(Path(directory).resolve(strict=True))
        self.lock = threading.Lock()
        self.loaded: tuple[Any, Any] | None = None
        self.precision = "float32-cpu"

    def _complete(self, messages: list[dict[str, str]]) -> str:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        with self.lock:
            if self.loaded is None:
                tokenizer = AutoTokenizer.from_pretrained(
                    self.directory, local_files_only=True, trust_remote_code=False
                )
                weights = (
                    AutoModelForCausalLM.from_pretrained(
                        self.directory,
                        local_files_only=True,
                        trust_remote_code=False,
                        use_safetensors=True,
                    )
                    .float()
                    .eval()
                )
                self.loaded = tokenizer, weights
            tokenizer, weights = self.loaded
            text = tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
            tokens = tokenizer(text, return_tensors="pt", truncation=True, max_length=3072)
            with torch.inference_mode():
                generated = weights.generate(
                    **tokens,
                    do_sample=False,
                    max_new_tokens=192,
                    max_time=60,
                    pad_token_id=tokenizer.eos_token_id,
                )
            return str(
                tokenizer.decode(
                    generated[0, tokens["input_ids"].shape[1] :], skip_special_tokens=True
                )
            )

    async def complete(self, messages: list[dict[str, str]], model: str) -> str:
        from anyio import to_thread

        return await to_thread.run_sync(self._complete, messages)


def configured_provider(kind: str) -> Provider:
    if kind == "mock":
        return MockProvider()
    if kind == "local-hf":
        return LocalHFProvider(os.environ["MECHA_LOCAL_MODEL_PATH"])
    return RealProvider(kind)
