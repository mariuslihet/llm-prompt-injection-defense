# Policy reference

The compiler uses YAML safe_load and pydantic with unknown fields forbidden.
`version` identifies the authored policy; its canonical SHA-256 digest binds
approvals to exact rules. `mode` is enforce or shadow. Shadow records what
would be denied while retaining structural enforcement for mock effects.

Each rule declares `tool`, the exact `arguments` set, whether the tool is
`external`, `trusted_arguments`, `url_arguments`, `allowed_hosts`, and
`approval_after_untrusted`. Unknown tools/argument names are denied. send_email
and fetch_url are intrinsically external even if a policy mislabels them.
The default YAML is packages/policy/default.yaml.

For an external call, every argument must include the tool in allowed_sinks,
be public, and meet any per-argument trust/URL constraint. URLs require HTTPS,
an exact host match, no credentials, and default/443 port. Host allowlisting
does not itself solve DNS rebinding; mock tools do not perform network I/O.
All external calls after any untrusted input require approval. Approval never
overrides private-data denial, destination taint or missing capabilities.

API workflow: GET /policy -> POST /policy/stage with dry_run true -> stage with
dry_run false -> review digest/revision -> POST /policy/promote. To roll back,
promote a prior tenant revision. Each action is audited. Revisions currently
live in memory; restart revokes staged edits. The PolicyStore class also
accepts a SQLite file for future persistent deployments, but the gateway does
not yet wire durable policy storage into production configuration.

Static verification rejects known external tools mislabeled as internal,
untrusted destination paths, and missing approval barriers. Run
`uv run mecha verify-policy packages/policy/default.yaml`; a violation exits
nonzero. It reasons about this AST, not arbitrary tool implementation code.

Public Python APIs: `compile_policy(text) -> Policy`, `evaluate(policy, tool,
arguments, read_untrusted=..., approved=...) -> Decision`, `verify(policy) ->
list[str]`, and `binding(tenant, policy, tool, arguments) -> str`.
`Approvals.issue` is an authority API; never expose it to an LLM. Remote clients
cannot submit Label or Value objects to make their own trust assertions.
