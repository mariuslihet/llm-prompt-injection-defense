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
        if set(event) - {
            "action",
            "rule",
            "reason",
            "request_id",
            "duration_ms",
            "model",
            "count",
            "trace",
        }:
            raise ValueError("non-metadata audit field")
        if "trace" in event:
            from packages.ifc.trace import ExecutionTrace

            ExecutionTrace.model_validate_json(str(event["trace"]))
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

    def incident(self, tenant: str, digest: str) -> dict[str, object] | None:
        with self.lock:
            row = self.db.execute(
                "SELECT event,digest FROM audit WHERE tenant=? AND digest=?", (tenant, digest)
            ).fetchone()
        if row is None:
            return None
        event = json.loads(row[0])
        if "trace" in event:
            event["trace"] = json.loads(event["trace"])
        return {"event": event, "digest": row[1]}

    def metrics(self, tenant: str) -> dict[str, object]:
        with self.lock:
            rows = self.db.execute("SELECT event FROM audit WHERE tenant=?", (tenant,)).fetchall()
        actions: dict[str, int] = {}
        rules: dict[str, int] = {}
        durations = []
        for (encoded,) in rows:
            event = json.loads(encoded)
            action, rule = event.get("action", "unknown"), event.get("rule", "unknown")
            actions[action] = actions.get(action, 0) + 1
            rules[rule] = rules.get(rule, 0) + 1
            if "duration_ms" in event:
                durations.append(event["duration_ms"])
        return {
            "total": len(rows),
            "actions": actions,
            "rules": rules,
            "block_rate": actions.get("block", 0) / len(rows) if rows else 0,
            "flag_rate": actions.get("flag", 0) / len(rows) if rows else 0,
            "p95_ms": sorted(durations)[max(0, (len(durations) * 95 + 99) // 100 - 1)]
            if durations
            else None,
        }
