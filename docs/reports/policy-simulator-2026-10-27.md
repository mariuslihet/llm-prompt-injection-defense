# Policy decision simulator — 2026-10-27

The Security Policy page now compares a sample `send_email` or `fetch_url`
decision without and with hypothetical human approval, using the tenant's active
policy. Operators can vary the origin, confidentiality, sink capability and
whether untrusted content was previously read. The interface explains the policy
decision and displays its rule and policy reference. Labels are hypothetical;
the simulator never issues approvals, executes tools or performs external actions.

Local browser verification:

- A trusted recipient and a permitted untrusted message required approval after
  reading untrusted content; the policy evaluation with hypothetical approval
  allowed that example.
- Changing the recipient to untrusted caused both evaluations to deny the
  example. Approval did not override the destination trust restriction.

Automated tests additionally cover private egress, including values that are both
private and untrusted, absent sink capability,
allowed and denied URLs, argument validation, authentication, viewer access,
and metadata-only audit logging. The full local suite passed 184 Python tests
with 99.18% configured security-core coverage; seven frontend/SDK tests, the
frontend build, Ruff and strict type checks passed. One upstream Starlette
deprecation warning remains. Tests make no network calls.

The simulator evaluates the active stored policy rather than unsaved editor text.
Its values and permissions are user-selected examples, not evidence about a real
agent. It does not prove an external tool or model integration applies the policy.
Production deployment, independent validation and general injection resistance
remain unverified.
