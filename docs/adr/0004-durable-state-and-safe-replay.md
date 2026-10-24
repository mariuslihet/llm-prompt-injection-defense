# ADR 0004: Durable control state and content-free replay

Accepted 2026-10-24. Configure MECHA_STATE_PATH to persist tenant key hashes,
approval grant hashes/expiry/bindings, rate-limit windows, policy revisions,
arena scores and reviewed fake-data corpus candidates. Default direct library
construction remains in-memory for tests. Example/Compose/Helm configs opt in.
Environment-provided tenant configuration explicitly overrides stored credentials
for the same name. Dynamic keys are displayed once; plaintext keys/grants are
never written to control storage. SQLite BEGIN IMMEDIATE serializes grant
consumption across connections. Persisted expiry uses host UTC wall time;
clock rollback and compromised database files are outside this claim.

Arena review payloads are now durable research data, separate from audit logs.
Only mock-command-preserving submissions are accepted. Operators must use fake
data and restrict filesystem access; these are not public untrusted submissions.
Metadata-only decision replay stores label classifications/counts, policy digest,
operation order and decisions in the audit hash chain. There is no field for
value contents, keys or prompts. Replay explains an execution; it does not
re-execute tools. Retaining full raw prompt replay would weaken data minimization.

This closes restart-loss gaps for SQLite, not the Postgres/shared production
architecture. Deployment certification still requires transactional Postgres
integration, real OS isolation, load tests and secret/identity management.
