"""In-process ASGI fast-path load check; excludes network/TLS/provider latency."""

import asyncio
import math
import statistics
import time

import httpx

from packages.gateway.app import Tenant, create_app
from packages.gateway.providers import MockProvider
from packages.telemetry import Audit


async def run(requests: int = 1000) -> dict[str, object]:
    if not 100 <= requests <= 100000:
        raise ValueError("requests must be between 100 and 100000")
    key = "fake-load-test-key"
    app = create_app(
        tenants={"load": Tenant(key=key, role="operator")},
        rate_limit=requests + 50,
        provider=MockProvider(),
        audit=Audit(),
        state_path=":memory:",
    )
    semaphore = asyncio.Semaphore(32)
    samples = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:

        async def one() -> None:
            async with semaphore:
                start = time.perf_counter_ns()
                response = await client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}"},
                    json={
                        "messages": [
                            {"role": "user", "content": "Summarize the public mock report."}
                        ]
                    },
                )
                response.raise_for_status()
                samples.append((time.perf_counter_ns() - start) / 1e6)

        await asyncio.gather(*(one() for _ in range(requests)))
    app.state.audit.close()
    return {
        "requests": requests,
        "concurrency": 32,
        "transport": "in-process ASGI, no sockets",
        "provider": "mock",
        "p50_ms": statistics.median(samples),
        "p95_ms": sorted(samples)[math.ceil(len(samples) * 0.95) - 1],
        "note": "Total fast-path request duration; excludes network, TLS and real inference.",
    }
