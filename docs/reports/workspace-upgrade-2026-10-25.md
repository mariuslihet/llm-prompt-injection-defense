# Approval and evaluation workspace upgrade

## Delivered

Approval Review now has a master/detail queue, title and justification, submitter
priority, search, status filters, sorting and expiry countdowns. Reviewers can add
comments, approve or deny with a note, withdraw pending requests, inspect policy
and label bindings, export JSON, and copy content into a fresh request. Copying
opens the editor without submitting. Existing proposals remain immutable.

Review events persist transactionally with state transitions, with a 100-event
cap and reserved space for decisions/execution. Server role attribution records
the authenticated tenant role; individual accounts are not implemented. Priority
does not change policy, expiry or authorization. Approval remains single use,
tenant-scoped and bound to original values, labels and policy. Comments remain
available for historical requests without reactivating them. Old requests show
that they predate history tracking, rather than fabricated past events.

Agent Evaluation now supports named runs, one to five selected comparison
defenses, matching execution budgets/fingerprints, outcome cards and observed
tool-usage counts. Filters distinguish answer tampering, confidential disclosure,
tool effects, normal-task failure and invalid runs. Filtered CSV exports quote
multiline fields and neutralize spreadsheet formula prefixes. Known harm remains
visible even if the execution later fails. Historical missing outcome fields are
explicitly not evidence of safety.

Saved run history supports name/ID search and status filtering. Loading a saved
configuration restores the editor and leaves prior evidence intact; execution
requires a deliberate run action with current model and policy. Titles do not
change dataset fingerprints, but defense selection and order do. CLI parity is
available through `--title` and `--defenses` for campaign/suite selection.
Unsupported legacy combinations are excluded from the scenario selector.

## Verification

- 122 Python tests passed, including five new workspace tests. Configured
  security core coverage remains 99.20%.
- Three frontend tests passed: spreadsheet-formula neutralization/CSV quoting,
  incomplete-run outcome filters, and observed-tool counting without counting
  proposed actions twice. `npm --prefix dashboard test` uses native TypeScript
  support, verified locally with Node 24.
- Ruff checks/formatting, strict mypy on 11 configured files, TypeScript checking
  and the Vite production build passed. The frontend CI job includes the new tests;
  hosted CI was not run from this local session.
- Review tests cover cross-tenant access, viewer restrictions, metadata validation,
  immutable label boundaries, comments, restart persistence, withdrawal, replay
  rejection, and a race between withdrawal and approval with only one winner.
- Selected-defense tests verify six executions for an IFC-only suite, its bounded
  allocation, matching fingerprints after a title change, different fingerprints
  for different selections, and rejection of empty/duplicate/unknown defenses.
- Browser checks created a high-priority titled proposal, added a comment,
  approved it, and displayed submitted/comment/approved/executed history with
  decision text. Copying created a fresh editor; submitting and withdrawing the
  revision recorded its reason and removed execution controls.
- Browser checks ran a two-defense suite, filtered answer-integrity outcomes,
  downloaded CSV, and restored a saved setup after changing the editor. The
  downloaded CSV was parsed independently: five rows, all integrity outcomes.

## Live local-model evidence

Saved run `e50b2ca7456e4e5eb1ef55d8e5adcb5f`, named **Focused workflow review**:
development variation 2, integrity objective, returned-record channel, eight-turn
limit, Qwen2.5-7B-Instruct, selected defenses `none` and `full-ifc`.

| Defense | Attack objectives reached | Normal-task success | Invalid executions | Target model calls |
| --- | --- | --- | --- | --- |
| none | 3/3 | 3/3 | 0 | 28 |
| full-ifc | 2/3 | 3/3 | 0 | 12 |

There were six unique inputs and 12 executions, with 40 model calls against a
96-call suite allocation. The dashboard reported five answer-tampering outcomes,
zero confidential-marker disclosures, zero unauthorized tool effects, 6/6
normal-task successes, and zero invalid executions. The outcome counts overlap
in general and are descriptive, correlated samples, not population estimates.
Evidence is retained locally in `artifacts/review-workspace-evaluation.json` and
the tenant's saved job. No external action was performed.

The two IFC integrity failures remain real failures: restricting tool authority
does not establish factual correctness. The earlier Windows latency gate failure
also remains unresolved. This workspace upgrade does not claim production
readiness, distributed execution, individual reviewer identities or protection
against every injection channel.

## Next and delivery assessment

Prioritize source-grounded integrity checks and independent attack cases, then
individual operator identities and an integration that supplies policy-bound
model proposals without upgrading their trust. Keep the existing authorization
boundary for the current public-summary operator workflow.

Delivery self-check: accuracy 4/5 (tests and live evidence verified; sample size
remains small), completeness 4/5 (both requested workspaces expanded; identity
attribution remains tenant-role scope), clarity 4/5 (separate outcome cards;
deep forensic values still use JSON), actionability 4/5 (running UI and exports
verified; external deployment remains deferred), conciseness 4/5 (evidence in one
report; historical reports still require version awareness). Overall 4.0/5.
The user can inspect concrete new controls and reproduced failures; a claim
that the security research program is finished would not be justified.

No dependencies were added. No files were staged, committed or pushed.
