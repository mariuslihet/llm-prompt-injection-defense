"""Tests must not accidentally call a model, DNS, or other network service."""

import socket
import threading

import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    original_connect = socket.socket.connect
    original_socketpair = socket.socketpair
    ipc = threading.local()

    def denied(*args, **kwargs):
        raise AssertionError("network access is forbidden in tests")

    def connect(sock, address):
        # Python 3.11 on Windows implements asyncio's internal wakeup pair over
        # loopback. Permit only the stdlib socketpair construction, never client I/O.
        if getattr(ipc, "socketpair", False):
            return original_connect(sock, address)
        return denied(sock, address)

    def socketpair(*args, **kwargs):
        ipc.socketpair = True
        try:
            return original_socketpair(*args, **kwargs)
        finally:
            ipc.socketpair = False

    monkeypatch.setattr(socket, "socketpair", socketpair)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
