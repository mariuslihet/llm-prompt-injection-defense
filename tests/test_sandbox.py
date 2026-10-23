import pytest

from packages.sandbox import GVisor, egress_allowed


def test_sandbox_fails_closed_and_has_no_host_access():
    sandbox = GVisor("python@sha256:" + "0" * 64)
    argv = sandbox.command(["python", "-c", "print('fake data')"])
    assert "--network=none" in argv and "--runtime=runsc" in argv and "--read-only" in argv
    assert not any(
        "volume" in value or "mount" in value or "docker.sock" in value for value in argv
    )
    with pytest.raises(RuntimeError):
        sandbox.run(["python", "-V"])
    with pytest.raises(ValueError):
        GVisor("python:latest")
    with pytest.raises(ValueError):
        sandbox.command([])


def test_egress_default_deny_and_resolved_private_destinations():
    url = "https://docs.example.invalid"
    assert not egress_allowed(url, frozenset(), ("8.8.8.8",))
    for ips in ((), ("127.0.0.1",), ("10.1.2.3",), ("::1",), ("bad",)):
        assert not egress_allowed(url, frozenset({"docs.example.invalid"}), ips)
    assert egress_allowed(url, frozenset({"docs.example.invalid"}), ("8.8.8.8",))
