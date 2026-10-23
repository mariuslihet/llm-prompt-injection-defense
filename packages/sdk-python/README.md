# Python SDK

The Python implementation is importable as `packages.sdk_python.Mecha` from the
single Mecha distribution. This directory preserves the requested SDK layout.
Use `await client.complete(text)` or iterate `client.stream(text)` for SSE JSON
data lines. Always `await client.close()`. Tool proposals must pass IFC rather
than being executed directly from text completions. See docs/INTEGRATIONS.md.
