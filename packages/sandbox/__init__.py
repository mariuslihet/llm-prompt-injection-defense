"""Opt-in Linux gVisor tool runner. Fails if isolation is unavailable."""

import asyncio
import ipaddress
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from packages.policy import allowed_url


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str


def egress_allowed(url: str, hosts: frozenset[str], resolved_ips: tuple[str, ...]) -> bool:
    """Decision primitive only; callers must pin resolution and recheck redirects.

    The shipped sandbox disables networking altogether. This predicate does
    not implement a DNS-safe network transport or enable networking.
    """
    if not allowed_url(url, hosts) or not resolved_ips:
        return False
    try:
        if urlsplit(url).hostname is None:
            return False
        return all(ipaddress.ip_address(ip).is_global for ip in resolved_ips)
    except ValueError:
        return False


class GVisor:
    def __init__(self, image: str) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9./_-]+@sha256:[0-9a-f]{64}", image):
            raise ValueError("sandbox image must be pinned by digest")
        self.image = image

    def command(self, argv: list[str], name: str | None = None) -> list[str]:
        if not argv or len(argv) > 32 or sum(map(len, argv)) > 65536:
            raise ValueError("invalid sandbox command")
        name = name or "mecha-" + uuid.uuid4().hex
        if not re.fullmatch(r"mecha-[0-9a-f]{32}", name):
            raise ValueError("invalid generated container name")
        return [
            "docker",
            "--host=unix:///var/run/docker.sock",
            "run",
            "--rm",
            "--name=" + name,
            "--pull=never",
            "--runtime=runsc",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=256m",
            "--cpus=1",
            "--user=65532:65532",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
            self.image,
            *argv,
        ]

    @staticmethod
    def _check(timeout: int) -> None:
        if (
            os.name != "posix"
            or os.getenv("MECHA_ENABLE_ISOLATION") != "1"
            or not shutil.which("docker")
        ):
            raise RuntimeError("Linux Docker with runsc and explicit opt-in required")
        if not 1 <= timeout <= 30:
            raise ValueError("sandbox timeout out of bounds")

    def run(self, argv: list[str], timeout: int = 10) -> SandboxResult:
        self._check(timeout)
        return asyncio.run(self.arun(argv, timeout))

    async def arun(self, argv: list[str], timeout: int = 10) -> SandboxResult:
        self._check(timeout)
        name = "mecha-" + uuid.uuid4().hex
        environment = {"PATH": os.environ.get("PATH", "")}
        process = await asyncio.create_subprocess_exec(
            *self.command(argv, name),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=environment,
        )

        async def collect() -> bytes:
            result = bytearray()
            if process.stdout is None:
                raise RuntimeError("sandbox output unavailable")
            while chunk := await process.stdout.read(4096):
                result.extend(chunk)
                if len(result) > 65536:
                    raise ValueError("sandbox output exceeds byte budget")
            await process.wait()
            return bytes(result)

        try:
            output = await asyncio.wait_for(collect(), timeout)
            return SandboxResult(process.returncode or 0, output.decode(errors="replace"), "")
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
            # Killing the Docker CLI does not necessarily stop its container.
            cleanup = await asyncio.create_subprocess_exec(
                "docker",
                "--host=unix:///var/run/docker.sock",
                "rm",
                "--force",
                name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                env=environment,
            )
            try:
                await asyncio.wait_for(cleanup.wait(), 5)
            except TimeoutError:
                cleanup.kill()
                await cleanup.wait()
