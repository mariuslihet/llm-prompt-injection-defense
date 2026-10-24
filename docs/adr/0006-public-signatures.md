# ADR 0006: Public-key integrity for tool definitions and audit checkpoints

Accepted 2026-10-24. Use optional cryptography for reviewed Ed25519 primitives;
do not implement cryptography ourselves. A catalog with trusted_signers set
requires a signature by that server's configured public key in addition to a
matching definition hash and permission scope. An explicitly empty signer map
denies all registrations. Leaving the option unset preserves hash-only mode.

Signed anchors bind an externally retained audit row count and chain digest.
Verification permits additional events but detects loss of the anchored prefix.
It cannot detect truncation after the newest retained anchor, or guarantee
availability. Operators must retain the signed anchor/public key outside the
database's writable boundary. Tests generate disposable keys in memory only;
no release-signing secret or production key is created or committed.
