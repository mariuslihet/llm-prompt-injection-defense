"""Transactional SQLite hash-chain. Stores decision metadata, never raw prompts."""

import hashlib
import json
import sqlite3
import threading
from pathlib import Path


class Audit:
    def __init__(self, path: str = ":memory:") -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, "
            "tenant TEXT NOT NULL, event TEXT NOT NULL, previous TEXT NOT NULL, "
            "digest TEXT NOT NULL)"
        )
        self.db.executescript("""
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
            BEGIN SELECT RAISE(ABORT, 'append only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
            BEGIN SELECT RAISE(ABORT, 'append only'); END;
        """)

    def append(self, tenant: str, event: dict[str, str | int | float | bool]) -> str:
        # An allowlist prevents accidental prompt, credential and PII logging.
        if set(event) - {"action", "rule", "reason", "request_id", "duration_ms", "model", "count"}:
            raise ValueError("non-metadata audit field")
        encoded = json.dumps({"tenant": tenant, **event}, sort_keys=True, separators=(",", ":"))
        with self.lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                last = self.db.execute(
                    "SELECT digest FROM audit ORDER BY id DESC LIMIT 1"
                ).fetchone()
                previous = last[0] if last else "0" * 64
                digest = hashlib.sha256((previous + encoded).encode()).hexdigest()
                self.db.execute(
                    "INSERT INTO audit (tenant,event,previous,digest) VALUES (?,?,?,?)",
                    (tenant, encoded, previous, digest),
                )
                self.db.commit()
                return digest
            except Exception:
                self.db.rollback()
                raise

    def verify(self) -> bool:
        previous = "0" * 64
        with self.lock:
            rows = self.db.execute("SELECT event,previous,digest FROM audit ORDER BY id").fetchall()
        for event, parent, digest in rows:
            if (
                parent != previous
                or hashlib.sha256((parent + event).encode()).hexdigest() != digest
            ):
                return False
            previous = digest
        return True

    def events(self, tenant: str) -> list[dict[str, object]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT event,digest FROM audit WHERE tenant=? ORDER BY id DESC LIMIT 200",
                (tenant,),
            ).fetchall()
        return [{"event": json.loads(event), "digest": digest} for event, digest in rows]

    def close(self) -> None:
        self.db.close()
