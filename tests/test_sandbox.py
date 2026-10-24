import pytest

from packages.sandbox import GVisor, egress_allowed


def test_sandbox_fails_closed_and_has_no_host_access():
    sandbox = GVisor("python@sha256:" + "0" * 64)
    argv = sandbox.command(["python", "-c", "print('fake data')"])
    assert "--network=none" in argv and "--runtime=runsc" in argv and "--read-only" in argv
    host_options = argv[: argv.index(sandbox.image)]
    assert not any(
        value.startswith(("--volume", "--mount", "--privileged")) for value in host_options
    )
    assert "--host=unix:///var/run/docker.sock" in host_options
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


@pytest.mark.anyio
async def test_sandbox_output_budget_kills_cli_and_removes_named_container(monkeypatch):
    class Output:
        async def read(self, size):
            return b"x" * size

    class Process:
        returncode = None
        stdout = Output()

        def kill(self):
            self.returncode = -9

        async def wait(self):
            self.returncode = self.returncode or 0
            return self.returncode

    process, commands = Process(), []

    async def start(*argv, **kwargs):
        commands.append(argv)
        return process if "run" in argv else Process()

    monkeypatch.setattr("packages.sandbox.os.name", "posix")
    monkeypatch.setenv("MECHA_ENABLE_ISOLATION", "1")
    monkeypatch.setattr("packages.sandbox.shutil.which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr("packages.sandbox.asyncio.create_subprocess_exec", start)
    with pytest.raises(ValueError, match="byte budget"):
        await GVisor("python@sha256:" + "0" * 64).arun(["python", "-V"])
    assert process.returncode == -9
    assert commands[1][2:4] == ("rm", "--force")
    assert commands[1][-1].startswith("mecha-")
