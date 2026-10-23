"""YAML-to-AST compiler and fail-closed, per-argument authorization."""

import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field

from packages.core import Confidentiality, Trust, Value


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tool: str = Field(pattern=r"^[a-z_]+$")
    arguments: frozenset[str] = Field(min_length=1)
    external: bool = False
    trusted_arguments: frozenset[str] = frozenset()
    url_arguments: frozenset[str] = frozenset()
    allowed_hosts: frozenset[str] = frozenset()
    approval_after_untrusted: bool = True


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: str = Field(min_length=1)
    mode: Literal["enforce", "shadow"] = "enforce"
    rules: tuple[Rule, ...]

    @property
    def digest(self) -> str:
        def canonical(value: object) -> object:
            if isinstance(value, dict):
                return {k: canonical(v) for k, v in sorted(value.items())}
            if isinstance(value, set | frozenset):
                return sorted(value)
            if isinstance(value, tuple | list):
                return [canonical(v) for v in value]
            return value

        encoded = json.dumps(canonical(self.model_dump()), sort_keys=True)
        return hashlib.sha256(encoded.encode()).hexdigest()


def compile_policy(text: str) -> Policy:
    if len(text) > 65536:
        raise ValueError("policy too large")
    policy = Policy.model_validate(yaml.safe_load(text))
    names = [r.tool for r in policy.rules]
    if len(names) != len(set(names)):
        raise ValueError("duplicate tool rules")
    for rule in policy.rules:
        if not (rule.trusted_arguments | rule.url_arguments) <= rule.arguments:
            raise ValueError("rule references an undeclared argument")
    return policy


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True)
    allowed: bool
    rule: str
    reason: str
    needs_approval: bool = False


def allowed_url(url: str, hosts: frozenset[str]) -> bool:
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname in hosts
            and parsed.username is None
            and parsed.password is None
            and parsed.port in (None, 443)
            and "\\" not in url
            and not any(ord(c) < 33 for c in url)
        )
    except ValueError:
        return False


def evaluate(
    policy: Policy,
    tool: str,
    arguments: dict[str, Value],
    *,
    read_untrusted: bool,
    approved: bool = False,
) -> Decision:
    rule = next((r for r in policy.rules if r.tool == tool), None)
    if rule is None or set(arguments) != rule.arguments:
        return Decision(allowed=False, rule="default-deny", reason="unknown tool or argument shape")
    if tool in {"send_email", "fetch_url"} and not rule.external:
        return Decision(allowed=False, rule="intrinsic-sink", reason="external tool mislabeled")
    for name, value in arguments.items():
        if name in rule.trusted_arguments and value.label.trust != Trust.TRUSTED:
            return Decision(allowed=False, rule=tool, reason=f"untrusted destination: {name}")
        if name in rule.url_arguments and not allowed_url(value.data, rule.allowed_hosts):
            return Decision(allowed=False, rule=tool, reason=f"URL denied: {name}")
        if rule.external and tool not in value.label.allowed_sinks:
            return Decision(allowed=False, rule=tool, reason=f"sink capability missing: {name}")
        if rule.external and value.label.confidentiality == Confidentiality.PRIVATE:
            return Decision(allowed=False, rule=tool, reason=f"private egress denied: {name}")
    if rule.external and read_untrusted and rule.approval_after_untrusted and not approved:
        return Decision(
            allowed=False, rule=tool, reason="human approval required", needs_approval=True
        )
    return Decision(allowed=True, rule=tool, reason="all argument constraints satisfied")


def verify(policy: Policy) -> list[str]:
    """Conservative graph check of source→argument→external-tool paths.

    A destination without a trust restriction or an external tool without an
    approval boundary is rejected. Dynamic IFC enforces private sink constraints.
    This verifies only this finite AST, not arbitrary programs or hidden tools.
    """
    problems = []
    for rule in policy.rules:
        if rule.tool in {"send_email", "fetch_url"} and not rule.external:
            problems.append(f"{rule.tool} is intrinsically external but policy says otherwise")
        if rule.external:
            destinations = rule.arguments & {"recipient", "url", "destination"}
            for name in destinations - rule.trusted_arguments:
                problems.append(f"untrusted->{rule.tool}.{name}->external has no trust barrier")
            if not rule.approval_after_untrusted:
                problems.append(f"untrusted-control->{rule.tool}->external has no approval barrier")
    return problems


def binding(tenant: str, policy: Policy, tool: str, arguments: dict[str, Value]) -> str:
    data = {
        "tenant": tenant,
        "policy": policy.digest,
        "tool": tool,
        "arguments": {
            k: {
                "data": v.data,
                "label": {
                    "sources": sorted(v.label.sources),
                    "trust": v.label.trust.value,
                    "confidentiality": v.label.confidentiality.value,
                    "allowed_sinks": sorted(v.label.allowed_sinks),
                },
            }
            for k, v in sorted(arguments.items())
        },
    }
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


class Approvals:
    """Thread-safe, one-use, opaque grants. Only the authenticated human API issues them."""

    def __init__(self) -> None:
        self._grants: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def issue(self, expected_binding: str, ttl: float = 300) -> str:
        if not 0 < ttl <= 300:
            raise ValueError("approval TTL out of bounds")
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._grants[token] = (expected_binding, time.monotonic() + ttl)
        return token

    def consume(self, token: str, expected_binding: str) -> bool:
        with self._lock:
            grant = self._grants.pop(token, None)
        return bool(
            grant
            and grant[1] > time.monotonic()
            and hmac.compare_digest(grant[0], expected_binding)
        )
