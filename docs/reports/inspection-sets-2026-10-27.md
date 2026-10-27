# Labeled inspection sets — 2026-10-27

Security Tests now provides a multi-input detector comparison. Operators can
edit, add and remove up to 12 sample inputs; label each as attack, ordinary or
unlabeled; inspect the set; see detections, misses and ordinary inputs flagged;
and download results with the original samples and labels. Per-input results
include the configured decision, indicators and sanitized preview. Changing an
input clears stale results. The operator's labels are not independently verified.

The local browser run used the three provided examples. The configured detector
flagged 1/2 labeled attacks, missed the access-approval instruction, and flagged
0/1 ordinary inputs. This exposes a real detection gap on this small set; it is
not a statistical benchmark or an agent attack-success rate. Flag and shadow
decisions count as findings while explicitly remaining non-blocking.

API checks cover block/flag/shadow modes, misses and false flags, unavailable
rates, unique IDs, length and count bounds, roles, metadata-only auditing, and
failure without partial results or exception disclosure. Tests make no network
calls. Invalid judge replies are marked inconclusive and excluded from rates,
even when the detector fails closed. Full local validation: 173 Python tests passed with 99.18% configured
security-core coverage; seven frontend/SDK tests, TypeScript checks, frontend
build, Ruff and strict core type checks passed. One upstream deprecation warning
remains. Hosted CI was not run.

The detector is not a structural security boundary and does not evaluate agent
actions. A configured judge may process samples with its configured provider.
The JSON download explicitly contains original sample text; use sample data.
Broader independently labeled cases and measured defenses remain necessary.
