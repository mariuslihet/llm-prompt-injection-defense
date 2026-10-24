import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from packages.gateway.mcp import Catalog, ToolDefinition  # noqa: E402
from packages.telemetry import Audit  # noqa: E402
from packages.telemetry.signing import anchor, sign, verify_anchor, verify_signature  # noqa: E402


def keys():
    private = Ed25519PrivateKey.generate()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def test_public_key_signature_rejects_changed_definition_or_unknown_server():
    private, public = keys()
    definition = ToolDefinition(
        server="fake", name="search", description="Search fake data.", input_schema={}
    )
    catalog = Catalog(
        {"fake/search": definition.digest}, {"fake": frozenset({"search"})}, {"fake": public}
    )
    signature = sign(definition.digest.encode(), private)
    assert catalog.register(definition, signature) == "fake/search"
    assert not verify_signature(b"changed", signature, public)
    with pytest.raises(ValueError, match="signature"):
        catalog.register(definition)
    with pytest.raises(ValueError, match="signature"):
        Catalog({}, {}, {}).register(definition, signature)


def test_external_anchor_detects_chain_truncation_but_allows_new_events():
    private, public = keys()
    audit = Audit()
    audit.append("fake", {"action": "allow", "rule": "test"})
    expected = anchor(audit)
    signature = sign(expected.payload(), private)
    audit.append("fake", {"action": "block", "rule": "test"})
    assert verify_anchor(audit, expected, signature, public)
    audit.db.execute("DROP TRIGGER audit_no_delete")
    audit.db.execute("DELETE FROM audit")
    assert audit.verify()  # A bare local hash chain cannot detect total truncation.
    assert not verify_anchor(audit, expected, signature, public)
