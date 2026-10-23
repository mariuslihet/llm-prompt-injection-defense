FROM python:3.11-slim@sha256:b7a9e5f6a93d6d4a31f129bbd4bdee69efccb6ded0fb230d78aafaf37af98377 AS build
WORKDIR /app
RUN pip install --no-cache-dir uv==0.13.5
COPY pyproject.toml uv.lock ./
COPY packages ./packages
COPY agents ./agents
COPY lab ./lab
COPY eval ./eval
COPY training ./training
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.11-slim@sha256:b7a9e5f6a93d6d4a31f129bbd4bdee69efccb6ded0fb230d78aafaf37af98377
RUN groupadd -g 10001 mecha && useradd -u 10001 -g mecha -M mecha
WORKDIR /app
COPY --from=build --chown=mecha:mecha /app /app
USER 10001:10001
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
CMD ["uvicorn", "packages.gateway.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
