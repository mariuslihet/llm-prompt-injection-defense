# Contributing

Keep attacks confined to repository-owned mock agents with fake data and
reserved example domains. Never include real secrets or personal information.
Do not execute arbitrary payloads outside the opt-in sandbox. Start changes
with a testable claim, add a regression for each fixed bypass, run the offline
suite, strict core typing, formatting, coverage and static policy verifier.
Run static/adaptive evaluation and inspect utility as well as attack success.

Use conventional commits, small reviewable changes, ADRs for architectural or
stack changes, and a one-line dependency rationale in the commit/PR. Never
upgrade an experiment from not-run to passed without a seeded configuration,
raw result, environment/model identifiers and utility measurements. Keep the
acceptance checklist and limitations current. Do not approve corpus submissions
without reviewing their fake-data scope and deterministic effect oracle.
