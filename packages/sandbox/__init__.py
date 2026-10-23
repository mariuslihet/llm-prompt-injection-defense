"""Opt-in Linux gVisor tool runner. Fails if isolation is unavailable."""

import ipaddress
import os
import re
import shutil
import subprocess
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

    def command(self, argv: list[str]) -> list[str]:
        if not argv or len(argv) > 32 or sum(map(len, argv)) > 65536:
            raise ValueError("invalid sandbox command")
        return [
            "docker",
            "run",
            "--rm",
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

    def run(self, argv: list[str], timeout: int = 10) -> SandboxResult:
        if (
            os.name != "posix"
            or os.getenv("MECHA_ENABLE_ISOLATION") != "1"
            or not shutil.which("docker")
        ):
            raise RuntimeError("Linux Docker with runsc and explicit opt-in required")
        if not 1 <= timeout <= 30:
            raise ValueError("sandbox timeout out of bounds")
        # No shell, host mounts, sockets, env forwarding or fallback runtime.
        process = subprocess.run(  # noqa: S603 -- explicit opt-in, shell=False, no host mounts
            self.command(argv),
            capture_output=True,
            timeout=timeout,
            check=False,
            env={"PATH": os.environ.get("PATH", "")},
        )
        return SandboxResult(
            process.returncode,
            process.stdout[:65536].decode(errors="replace"),
            process.stderr[:65536].decode(errors="replace"),
        )
