# Content inspection — 2026-10-27

The Security Tests page now accepts operator-provided sample text from email,
web, document, retrieval, tool output, memory and other sources. It shows the
configured detector action, indicators, heuristic score, sanitized preview and
changes. Source selection labels the sample only; it does not alter rules.
Results are cleared when the input or source changes. Concurrent input or tenant
changes cannot display a stale result as the current one.

`POST /inspection` requires an operator or administrator tenant key. It validates
the source and text length, uses the existing detector and sanitizer, and appends
only decision metadata to the audit log. Detector errors return 503. Inspection
does not execute an agent workflow or tool. A configured detector may use an
opt-in classifier or judge; a judge can use its configured provider. The score is
not a probability and a clean result is not proof of safety.

Browser verification: a sample web instruction to ignore prior instructions was
reported as a block by the configured detector; a non-allowlisted example URL was
replaced in the preview. This is one example, not a detection benchmark. Tests
cover authentication, roles, all seven source labels with ordinary sample text,
validation, shadow mode, detector failure, sanitization and absence of sample
content in audit events. The full suite passed 163 Python tests with 99.18%
configured security-core coverage; six frontend tests, the production build,
Ruff and strict core type checks also passed. One Starlette deprecation warning
remains. No network calls were made by the tests.

The existing architecture limitations remain: text inspection cannot reliably
identify every attack, determine source truth, prevent actions performed outside
Mecha or establish production readiness. Broader adversarial evaluation and
independent deployment verification are still needed.
