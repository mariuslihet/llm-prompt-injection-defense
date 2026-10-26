# ADR 0012: source-grounded workflow answers

Accepted 2026-10-26 for the three scoped record workflows.

Validate model-extracted fields against structured records returned by configured
server-owned read adapters. Invoice fields are copied from the invoice after
vendor linkage/status checks. Support routing/severity uses explicit issue-code
and impact fields. Access decisions use the manager-approval record. Free-text
notes never define these rules. Missing, conflicting or unsupported evidence
fails closed in enforce mode. No evaluation expected-answer table is consulted.

Keep the proposed fields and per-field source/rule explanations in sample-data
traces. Enforce returns canonical grounded fields; shadow reports differences
without changing the answer; off preserves the earlier IFC behavior. All labels
are conservatively joined, never upgraded. The final restricted-program answer
must preserve the canonical grounded serialization in enforce mode.

Mode is treatment configuration, like policy, rather than a dataset input.
Matched comparisons may change mode and must report that change explicitly.
Existing historical runs without a mode predate this control and mean off.

This establishes agreement with the configured structured sources, not universal
truth or integrity of arbitrary websites, emails, record fields or adapters.
An attacker able to corrupt authoritative structured fields is outside this
covered boundary. No real external effects or new dependencies are introduced.
