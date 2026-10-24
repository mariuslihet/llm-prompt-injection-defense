"""Load only the repository-owned mock service on fixed loopback port 8001."""

import argparse
import asyncio
import json
import math
import statistics
import time
from pathlib import Path

import httpx


async def measure(requests: int = 1000, concurrency: int = 16) -> dict[str, object]:
    if not 100 <= requests <= 10000 or not 1 <= concurrency <= 64:
        raise ValueError("load budget out of bounds")
    durations, server_durations, errors = [], [], []
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8001",
        timeout=10,
        trust_env=False,
        limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
    ) as client:
        health = await client.get("/health")
        if health.json().get("provider") != "MockProvider":
            raise ValueError("load target must be the mock gateway")

        async def one() -> None:
            async with semaphore:
                start = time.perf_counter_ns()
                response = await client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": "Bearer fake-loopback-load-key"},
                    json={
                        "messages": [{"role": "user", "content": "Summarize the public report."}]
                    },
                )
                durations.append((time.perf_counter_ns() - start) / 1e6)
                if response.headers.get("server-timing", "").startswith("mecha;dur="):
                    server_durations.append(
                        float(response.headers["server-timing"].split("=", 1)[1])
                    )
                if response.status_code != 200:
                    errors.append(response.status_code)

        await asyncio.gather(*(one() for _ in range(requests)))
    return {
        "requests": requests,
        "concurrency": concurrency,
        "transport": "loopback TCP HTTP/1.1",
        "provider": "mock",
        "p50_ms": statistics.median(durations),
        "p95_ms": sorted(durations)[math.ceil(len(durations) * 0.95) - 1],
        "server_p95_ms": sorted(server_durations)[math.ceil(len(server_durations) * 0.95) - 1]
        if server_durations
        else None,
        "errors": len(errors),
        "limits": "Localhost mock only; no TLS, real inference or public deployment.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("artifacts/network-load.json"))
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=16)
    args = parser.parse_args()
    report = asyncio.run(measure(args.requests, args.concurrency))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))
    raise SystemExit(bool(report["errors"]) or report["p95_ms"] >= 50)
