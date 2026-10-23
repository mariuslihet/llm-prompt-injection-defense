.PHONY: setup test check demo-attack eval serve
setup:
	uv sync --frozen
test:
	uv run pytest --cov --cov-report=term-missing
check:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy
demo-attack:
	uv run mecha demo-attack
eval:
	uv run mecha evaluate --output docs/reports/latest
serve:
	uv run uvicorn packages.gateway.app:app --host 127.0.0.1 --port 8000
