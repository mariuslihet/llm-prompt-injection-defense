"""Transactional SQLite control state. Only hashes of API keys/grants are stored."""

import hashlib
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from packages.policy import Approvals


class Identity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    role: Literal["viewer", "operator", "admin"]
    platform_admin: bool = False


class State:
    def __init__(self, path: str = ":memory:") -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.lock = threading.RLock()
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS tenants (
            name TEXT PRIMARY KEY, key_hash TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL, platform_admin INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS grants (
            token_hash TEXT PRIMARY KEY, binding TEXT NOT NULL, expires REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS request_windows (tenant TEXT NOT NULL, at REAL NOT NULL);
          CREATE INDEX IF NOT EXISTS request_windows_time ON request_windows(at);
        """)

    @staticmethod
    def digest(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def seed(self, name: str, key: str, identity: Identity) -> None:
        """Trusted environment config takes precedence over persisted credentials."""
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO tenants VALUES (?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                "key_hash=excluded.key_hash, role=excluded.role, "
                "platform_admin=excluded.platform_admin",
                (name, self.digest(key), identity.role, identity.platform_admin),
            )

    def authenticate(self, key: str) -> tuple[str, Identity] | None:
        with self.lock:
            row = self.db.execute(
                "SELECT name,role,platform_admin FROM tenants WHERE key_hash=?", (self.digest(key),)
            ).fetchone()
        return (row[0], Identity(role=row[1], platform_admin=bool(row[2]))) if row else None

    def create_tenant(self, name: str, role: str) -> str:
        identity = Identity(role=role)
        key = secrets.token_urlsafe(32)
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO tenants VALUES (?,?,?,0)", (name, self.digest(key), identity.role)
            )
        return key

    def tenants(self) -> list[dict[str, str]]:
        with self.lock:
            rows = self.db.execute("SELECT name,role FROM tenants ORDER BY name").fetchall()
        return [{"name": name, "role": role} for name, role in rows]

    def allow_request(self, tenant: str, limit: int) -> bool:
        now = time.time()
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("DELETE FROM request_windows WHERE at<=?", (now - 60,))
            count = self.db.execute(
                "SELECT COUNT(*) FROM request_windows WHERE tenant=?", (tenant,)
            ).fetchone()[0]
            if count >= limit:
                return False
            self.db.execute("INSERT INTO request_windows VALUES (?,?)", (tenant, now))
        return True

    def close(self) -> None:
        self.db.close()


class StateApprovals(Approvals):
    """Atomic one-use grants shared by connections; persisted expiry uses UTC wall time."""

    def __init__(self, state: State) -> None:
        self.state = state

    def issue(self, expected_binding: str, ttl: float = 300) -> str:
        if not 0 < ttl <= 300:
            raise ValueError("approval TTL out of bounds")
        token, now = secrets.token_urlsafe(32), time.time()
        with self.state.lock, self.state.db:
            self.state.db.execute("BEGIN IMMEDIATE")
            self.state.db.execute("DELETE FROM grants WHERE expires<=?", (now,))
            if self.state.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] >= 10000:
                raise ValueError("approval capacity reached")
            self.state.db.execute(
                "INSERT INTO grants VALUES (?,?,?)",
                (self.state.digest(token), expected_binding, now + ttl),
            )
        return token

    def consume(self, token: str, expected_binding: str) -> bool:
        import hmac

        with self.state.lock, self.state.db:
            self.state.db.execute("BEGIN IMMEDIATE")
            row = self.state.db.execute(
                "SELECT binding,expires FROM grants WHERE token_hash=?", (self.state.digest(token),)
            ).fetchone()
            self.state.db.execute(
                "DELETE FROM grants WHERE token_hash=?", (self.state.digest(token),)
            )
        return bool(row and row[1] > time.time() and hmac.compare_digest(row[0], expected_binding))
