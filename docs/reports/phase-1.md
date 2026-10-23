# Phase 1: defense gateway prototype

Built a text proxy for OpenAI/Anthropic response shapes with sanitized SSE,
per-tenant API keys, roles, rate limits, hooks, context labeling, heuristic
detector and conservative output sanitizer. Real providers require explicit
MECHA_ALLOW_NETWORK=1 and credentials; none were called. SQLite audit uses
transactional append-only triggers and a SHA-256 chain; raw prompts are excluded.

Initial local run: 29 tests passed across phases 0-3; core module coverage 99.2%.
Load run: 1,000 requests, concurrency cap 32, in-process ASGI, p95 1.2706 ms.
No TLS/network/inference is included. See load.json for machine-readable data.

Static fixture ASR fell from 100% to 0% under heuristics. Adaptive fixture ASR
returned to 100%. On 336 benign fixture tasks, heuristic FPR was 7.14% and
utility 92.86%. Sanitizing text added no protection against tool effects.

Not accepted as complete: no trained/calibrated production classifier or judge,
complete drop-in protocol compatibility, native incremental provider streaming,
distributed auth/limits, actual upstream interoperability or deployed load test.
Dependency audit found vulnerable initial pins; remediation is being verified.
