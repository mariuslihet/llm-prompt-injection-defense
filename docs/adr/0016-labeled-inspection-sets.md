# ADR 0016: bounded labeled inspection sets

Accepted 2026-10-27. Extend the existing content preview with operator-labeled
sets of 1–12 samples, each bounded to 4,096 characters. Execute inspections
sequentially using the same configured detector and sanitizer as single-content
inspection. Return no partial results if any inspection fails. The audit records
only the count and action; original sample text is included only in the explicit
local JSON download and request, not audit metadata.

Count `block`, `flag` and `shadow` as detector findings, while preserving the
actual action on every result. Calculate missed attacks and ordinary inputs
flagged from operator-supplied labels; use null when a rate has no denominator.
Unlabeled inputs do not affect rates. Source is descriptive, not a trust label.
An invalid judge response is inconclusive and excluded from rates even when the
detector fails closed; the original action remains visible.
This is not agent attack success or a validated benchmark. No new dependencies,
tool execution or automatic data submissions are introduced.
