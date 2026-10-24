"""Repository-owned mock server for loopback TCP load measurement, never deploy publicly."""

from packages.gateway.app import Tenant, create_app
from packages.gateway.providers import MockProvider

app = create_app(
    tenants={"load": Tenant(key="fake-loopback-load-key", role="operator")},
    rate_limit=100000,
    provider=MockProvider(),
)
