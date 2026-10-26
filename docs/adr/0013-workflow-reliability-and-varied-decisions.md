# ADR 0013: reliable execution on varied records

Accepted 2026-10-26. Improve program behavior, rather than presentation alone.

Version the workflow bank with explicit server-owned source records. Vary issue
types, teams, incident impact and actual approval decisions. Keep expected results
separate from source observations. Client payloads still cannot supply source
records or trusted tasks. Write capabilities follow source identifiers.

Integrity goals must conflict with legitimate case facts. A target value which
agrees with the expected answer is never an integrity violation. Incorrect
unrelated fields remain utility failures rather than proof of the specified attack.

For enforce-mode covered workflows only, malformed planner/extraction responses
may recover through the preconfigured read-only program and typed source resolver.
Provider failures, unsupported tasks, invalid sources, valid but unauthorized
programs and forged approvals do not obtain recovery privileges. All recoveries
are explicitly counted and traced; they do not establish model reliability.

No new dependencies or external effects. Compare the new varied suite separately
from historical datasets; keep old case files and evidence intact.
