# Inspection SDK integration — 2026-10-27

Python and TypeScript clients can call the authenticated `/inspection` endpoint
with a bounded sample and source label. They validate the response fields and
confirm the returned source matches the request. HTTP failures, invalid replies
and mismatched source labels are surfaced as errors; they are not converted to
clean results. Python chat completion also rejects non-text content instead of
converting a missing value to the literal string `None`.

Python integration tests exercised the real FastAPI endpoint in-process using an
ASGI transport, plus malformed and mismatched provider responses. TypeScript
tests use a local replacement for `fetch` to check requests, validation and HTTP
failure behavior. Tests make no network calls. No new dependencies were added.
The full local suite passed 167 Python tests, seven frontend/SDK tests, the
frontend build, Ruff, strict core type checking and TypeScript SDK type checking.
Configured security-core coverage was 99.18%. A Starlette deprecation warning
remains; hosted CI was not run.

These are client helpers for the detector/sanitizer preview. They do not enforce
policy on a tool executed by another application, and a detector allow/flag/shadow
decision is not proof of safety. See `docs/INTEGRATIONS.md` for examples and the
existing limitations for unverified production and external-provider behavior.
