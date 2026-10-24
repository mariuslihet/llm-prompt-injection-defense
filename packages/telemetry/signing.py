"""Ed25519 signatures for public MCP manifests and externally retained audit anchors."""

import base64
import json

from pydantic import BaseModel, ConfigDict, Field

from packages.telemetry import Audit


def sign(payload: bytes, private_key: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(private_key).sign(payload)
    ).decode()


def verify_signature(payload: bytes, signature: str, public_key: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            base64.b64decode(signature, validate=True), payload
        )
        return True
    except (InvalidSignature, ValueError):
        return False


class Anchor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    count: int = Field(ge=0)
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    def payload(self) -> bytes:
        return json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":")).encode()


def anchor(audit: Audit) -> Anchor:
    with audit.lock:
        row = audit.db.execute("SELECT COUNT(*),MAX(id) FROM audit").fetchone()
        head = audit.db.execute("SELECT digest FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    return Anchor(count=row[0], digest=head[0] if head else "0" * 64)


def verify_anchor(audit: Audit, expected: Anchor, signature: str, public_key: bytes) -> bool:
    if not verify_signature(expected.payload(), signature, public_key) or not audit.verify():
        return False
    with audit.lock:
        rows = audit.db.execute(
            "SELECT digest FROM audit ORDER BY id LIMIT ?", (expected.count,)
        ).fetchall()
    if len(rows) != expected.count:
        return False
    return (rows[-1][0] if rows else "0" * 64) == expected.digest
