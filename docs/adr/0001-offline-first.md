# ADR 0001: Offline evidence and explicit completion status

Accepted. Use the requested llm-prompt-injection-defense folder as repository
root. Use one Python distribution with packages for the requested subsystems;
this keeps cross-package label types consistent during initial development.
All default providers and tools are deterministic and local. Network-backed
providers and training remain opt-in and cannot replace acceptance evidence.
Generate attack data with diverse templates and store the expanded records;
do not call template variants independent real-world attacks. No mock may
claim to implement Firecracker, trained classifiers or upstream benchmarks.

Dependencies: FastAPI/uvicorn serve the gateway; pydantic validates untrusted
schemas; httpx supports optional providers; PyYAML parses policy with safe_load;
pytest/hypothesis/coverage verify contracts; ruff/mypy enforce code quality;
uv pins the dependency graph. Heavy ML dependencies will be optional.
