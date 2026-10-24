"""Default-deny HTTPS egress with public-IP DNS pinning and hostname-verified TLS."""

import http.client
import os
import socket
import ssl
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from packages.core import Value
from packages.policy import Policy, evaluate
from packages.sandbox import egress_allowed


class EgressResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: int
    text: str
    content_type: str


class PinnedHTTPS(http.client.HTTPSConnection):
    """Connect to the validated numeric IP, while authenticating the original hostname."""

    def __init__(self, host: str, address: str) -> None:
        super().__init__(host, port=443, timeout=5, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class EgressProxy:
    """Trusted server-side adapter; callers supply IFC Values, never raw model URLs."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def fetch(self, url: Value, *, read_untrusted: bool, approved: bool = False) -> EgressResult:
        decision = evaluate(
            self.policy, "fetch_url", {"url": url}, read_untrusted=read_untrusted, approved=approved
        )
        if not decision.allowed or os.getenv("MECHA_ALLOW_NETWORK") != "1":
            raise PermissionError("egress denied")
        parsed = urlsplit(url.data)
        host = parsed.hostname
        if host is None:
            raise PermissionError("missing egress host")
        rule = next(rule for rule in self.policy.rules if rule.tool == "fetch_url")
        addresses = tuple(
            sorted(
                {entry[4][0] for entry in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
            )
        )
        if not egress_allowed(url.data, rule.allowed_hosts, addresses):
            raise PermissionError("private, reserved or ambiguous DNS resolution denied")
        # A numeric address is pinned for this connection. Redirects never get
        # another DNS lookup or authority; each caller must authorize a new URL.
        connection = PinnedHTTPS(host, addresses[0])
        try:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request("GET", path, headers={"Host": host, "User-Agent": "Mecha/0.1"})
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise PermissionError("egress redirects denied")
            body = response.read(65537)
            if len(body) > 65536:
                raise ValueError("egress response exceeds byte budget")
            return EgressResult(
                status=response.status,
                text=body.decode("utf-8", errors="replace"),
                content_type=response.getheader("content-type", "application/octet-stream"),
            )
        finally:
            connection.close()
