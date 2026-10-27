# ADR 0015: bounded content inspection

Accepted 2026-10-27. Provide authenticated operators a way to inspect arbitrary
sample text without requiring the scripted attack format or running an agent.
The endpoint uses the existing configured detector and sanitizer, returns their
decision, indicators and sanitized preview, and appends metadata only to audit.
Content is limited to 32,768 characters; source labels are descriptive and do
not alter trust, rules or tool authority. Viewers cannot submit inspections.
Detector failure returns an error rather than an allow decision.

The configured cascade may include a classifier or opt-in judge, potentially
using its configured provider. The interface therefore asks for sample data and
does not claim all inspection is model-free. The preview performs no agent
workflow, no tool execution and no autonomous egress. Detection is probabilistic
and sanitation cannot undo effects. This does not establish general prompt
injection protection. No dependencies were added.
