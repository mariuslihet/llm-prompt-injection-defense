# ADR 0011: review history and focused evaluations

Accepted for the private local MVP.

Review titles, priorities, justification and role-attributed comments are workflow
metadata, never authority or policy overrides. Decisions remain bound to the
original arguments, labels, tenant, expiry and policy. Pending proposals may be
withdrawn; changing a proposal requires a fresh submission and review. Review
history is transactionally stored with state transitions, bounded to 100 entries.
Role attribution identifies the authenticated tenant role, not an individual user.

Evaluations may select one to five distinct supported defenses. Execution, budgets,
dataset fingerprints and summaries use that selection. Human-readable run titles
are persisted but do not change the dataset fingerprint. Loading a saved setup
copies its specification into the editor; a new run uses the current model and
policy, with a fresh job identity. It does not overwrite earlier evidence.

CSV exports neutralize spreadsheet formula prefixes in untrusted fields. No new
dependencies, remote services or Git mutations are needed.
