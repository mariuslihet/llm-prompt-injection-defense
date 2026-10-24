"""Pinned mock MCP catalog with server scoping and rug-pull/shadow detection."""

import hashlib
import hmac
import json

from pydantic import BaseModel, ConfigDict, Field

from packages.detectors import detect


class ToolDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    server: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    description: str = Field(max_length=4096)
    input_schema: dict[str, object]

    @property
    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.model_dump(), sort_keys=True).encode()).hexdigest()


class Catalog:
    def __init__(
        self,
        pins: dict[str, str],
        permissions: dict[str, frozenset[str]],
        trusted_signers: dict[str, bytes] | None = None,
    ) -> None:
        self.pins, self.permissions = pins.copy(), permissions.copy()
        self.tools: dict[str, ToolDefinition] = {}
        self.names: dict[str, str] = {}
        self.signers = None if trusted_signers is None else trusted_signers.copy()

    def register(self, definition: ToolDefinition, signature: str = "") -> str:
        if self.signers is not None:
            from packages.telemetry.signing import verify_signature

            public_key = self.signers.get(definition.server)
            if public_key is None or not verify_signature(
                definition.digest.encode(), signature, public_key
            ):
                raise ValueError("untrusted MCP definition signature")
        key = f"{definition.server}/{definition.name}"
        expected = self.pins.get(key, "")
        if not hmac.compare_digest(expected, definition.digest):
            raise ValueError("unpinned definition or MCP rug pull")
        if detect(definition.description).action == "block":
            raise ValueError("MCP description poisoning")
        if definition.name in self.names and self.names[definition.name] != definition.server:
            raise ValueError("cross-server tool shadowing")
        if definition.name not in self.permissions.get(definition.server, frozenset()):
            raise ValueError("server permission denied")
        self.tools[key], self.names[definition.name] = definition, definition.server
        return key

    def authenticate_manifest(self, manifest: bytes, signature: str, key: bytes) -> bool:
        """HMAC integrity for a trusted operator key; not a public-key signature."""
        return hmac.compare_digest(hmac.new(key, manifest, hashlib.sha256).hexdigest(), signature)
