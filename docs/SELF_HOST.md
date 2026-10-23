# Self-hosting, backup and upgrades

The supported verified path is a single local Python gateway and Vite console.
Keep the gateway on loopback, use fake data, and keep model tools behind IFC.
Do not expose the current arena publicly. Current grants, policy edits, limits,
leaderboard and review payloads reset on restart. Only the configured SQLite
audit is durable. No PostgreSQL migration/shared state service is implemented.

Docker assets: copy .env.example to .env, then run
`docker compose -f deploy/docker/compose.yaml up --build`.
The gateway uses non-root UID 10001, a read-only filesystem, dropped capabilities,
an internal network, and a persistent audit volume. Ensure volume permissions
allow UID 10001 to write. Docker/Compose are absent on the implementation host;
this command has not been verified. The official Python image index is pinned
by digest, resolved from Docker Hub on 2026-10-23. Container build and runtime
scans still require a Linux/Docker acceptance run.

Helm: create a Kubernetes Secret named mecha-tenants with key tenant-keys
containing the JSON tenant mapping, build/push your image, and run
`helm upgrade --install mecha deploy/helm --set image.repository=YOUR_IMAGE
--set image.digest=sha256:YOUR_DIGEST`. The chart keeps one replica and denies
egress. Ingress permits only pods labeled mecha-client=true. Confirm your CNI
enforces NetworkPolicy. TLS ingress and identity integration require deployment
configuration. Helm and Kubernetes were unavailable here; templates are untested.

## Isolation

GVisor requires Linux, Docker configured with the runsc runtime, a pre-pulled
digest-pinned image, and MECHA_ENABLE_ISOLATION=1. `GVisor.run` has no fallback
to a weaker runtime and disables networking, mounts, host sockets and inherited
environment. Timeout returns an error, not trusted output. The current runner
does not implement a bounded streaming output collector or guaranteed cleanup
after a host crash; it is not ready to accept public hostile code. Firecracker
and a DNS-pinned forwarding egress proxy remain unimplemented.

## Backup / restore

For a file-backed audit: `uv run python deploy/backup.py backup
artifacts/audit.sqlite artifacts/audit-backup.sqlite`. It uses SQLite backup
and verifies the chain. Stop the gateway before restoring to a **fresh** path:
`uv run python deploy/backup.py restore artifacts/audit-backup.sqlite
artifacts/restored.sqlite`. Point MECHA_AUDIT_PATH to the restored file. The
script refuses to overwrite evidence. Secure external chain anchors separately;
the local chain cannot detect total database replacement.

## Upgrade

Stop the single worker, snapshot the audit, preserve tenant config outside Git,
review changed policy digests and SECURITY_CLAIMS, then install with uv sync
--frozen. Run tests, corpus regression gate, and backup/restore verification
before resuming. Outstanding grants are revoked by restart. No database schema
migration automation or rolling distributed upgrade is certified.
