# ADR 0018: policy decision simulation

Accepted 2026-10-27. Add a read-only policy simulator for bounded sample email
and URL arguments. Compare the same server-evaluated values without and with
hypothetical approval under the authenticated tenant's active policy. The operator
selects hypothetical trust, confidentiality and sink capability; these labels
never enter an execution path. The simulator does not issue, consume or create
approval tokens, run tools or cause external effects. An audit entry contains
metadata only. It intentionally does not evaluate unsaved policy-editor text.

The simulation makes trust, confidentiality, destination and capability rules
visible without implying a detector is an authorization boundary. It cannot
establish the provenance of a real agent's arguments or certify external tool
enforcement. Any real effect must use a separately authorized policy path.
