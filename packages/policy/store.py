"""Tenant-scoped immutable policy revisions and explicit staged promotion."""

import sqlite3
import threading

from packages.policy import Policy, compile_policy, verify


class PolicyStore:
    def __init__(self, default_text: str, path: str = ":memory:") -> None:
        self.default_text = default_text
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS policies (
            tenant TEXT, revision INTEGER, text TEXT NOT NULL,
            PRIMARY KEY(tenant,revision));
          CREATE TABLE IF NOT EXISTS active_policy (
            tenant TEXT PRIMARY KEY, revision INTEGER NOT NULL);
        """)

    def get(self, tenant: str) -> Policy:
        return compile_policy(self.text(tenant))

    def text(self, tenant: str) -> str:
        with self.lock:
            row = self.db.execute(
                "SELECT p.text FROM policies p JOIN active_policy a "
                "ON p.tenant=a.tenant AND p.revision=a.revision WHERE p.tenant=?",
                (tenant,),
            ).fetchone()
        return row[0] if row else self.default_text

    def stage(self, tenant: str, text: str) -> int:
        errors = verify(compile_policy(text))
        if errors:
            raise ValueError("; ".join(errors))
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT COALESCE(MAX(revision),0)+1 FROM policies WHERE tenant=?", (tenant,)
            ).fetchone()
            revision = int(row[0])
            self.db.execute("INSERT INTO policies VALUES (?,?,?)", (tenant, revision, text))
        return revision

    def promote(self, tenant: str, revision: int) -> None:
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT text FROM policies WHERE tenant=? AND revision=?", (tenant, revision)
            ).fetchone()
            if not row:
                raise ValueError("unknown tenant policy revision")
            self.db.execute(
                "INSERT INTO active_policy VALUES (?,?) ON CONFLICT(tenant) "
                "DO UPDATE SET revision=excluded.revision",
                (tenant, revision),
            )

    def history(self, tenant: str) -> list[dict[str, object]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT revision,text FROM policies WHERE tenant=? ORDER BY revision DESC",
                (tenant,),
            ).fetchall()
        return [
            {"revision": revision, "digest": compile_policy(text).digest} for revision, text in rows
        ]
