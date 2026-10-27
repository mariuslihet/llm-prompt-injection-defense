# ADR 0017: approval-bypass review indicator

Accepted 2026-10-27. Add a narrow lexical indicator for approval wording near
missing/no/without approval, after the sample detector comparison exposed this
gap. Unicode normalization is inherited from the existing detector. Explain the
signal in both individual and set inspection.

The indicator alone uses `flag` under block mode because a training quotation
was incorrectly flagged during local utility testing. Independent existing
heuristics or a configured classifier/judge reaching the threshold can still
produce the configured block decision. Explicit flag and shadow modes remain
non-blocking. This indicator does not grant or deny tool capability; the policy
and approval checks remain the enforcement boundary.

The rule is not semantic understanding. A paraphrase evaded it in adaptive
testing, and it flags some legitimate quotations. Report both outcomes rather
than asserting general detection or protection. No new dependencies were added.
