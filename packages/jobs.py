"""Bounded durable single-worker jobs. Tenant isolation is enforced in every query."""

import asyncio
import hashlib
import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Awaitable, Callable

from lab.campaigns import RunSpec

TERMINAL = ("completed", "failed", "cancelled", "interrupted")


class JobConflict(ValueError):
    pass


class JobCapacity(ValueError):
    pass


class Jobs:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        if path != ":memory:":
            self.db.execute("PRAGMA journal_mode=WAL")
        self.lock = threading.RLock()
        self.db.execute("""CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY, tenant TEXT NOT NULL, request_key TEXT NOT NULL,
            spec_hash TEXT NOT NULL, spec TEXT NOT NULL, status TEXT NOT NULL,
            created REAL NOT NULL, updated REAL NOT NULL, result TEXT NOT NULL,
            UNIQUE(tenant,request_key))""")
        self.db.execute("CREATE INDEX IF NOT EXISTS jobs_tenant_created ON jobs(tenant,created)")
        with self.db:
            self.db.execute(
                "UPDATE jobs SET status='interrupted',updated=? "
                "WHERE status IN ('queued','running')",
                (time.time(),),
            )
        self.tasks: dict[str, asyncio.Task] = {}
        self.slot = asyncio.Semaphore(1)

    def create(self, tenant: str, spec: RunSpec, request_key: str) -> tuple[str, bool]:
        encoded = spec.model_dump_json()
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            existing = self.db.execute(
                "SELECT id,spec_hash FROM jobs WHERE tenant=? AND request_key=?",
                (tenant, request_key),
            ).fetchone()
            if existing:
                if existing[1] != digest:
                    raise JobConflict("idempotency key reused with a different request")
                return existing[0], False
            active = self.db.execute(
                "SELECT COUNT(*) FROM jobs WHERE tenant=? AND status IN ('queued','running')",
                (tenant,),
            ).fetchone()[0]
            global_active = self.db.execute(
                "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')"
            ).fetchone()[0]
            count = self.db.execute(
                "SELECT COUNT(*) FROM jobs WHERE tenant=?", (tenant,)
            ).fetchone()[0]
            if active >= 2 or global_active >= 8 or count >= 200:
                raise JobCapacity("job quota reached")
            identity, now = uuid.uuid4().hex, time.time()
            self.db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,'queued',?,?,?)",
                (identity, tenant, request_key, digest, encoded, now, now, "{}"),
            )
        return identity, True

    def get(self, tenant: str, identity: str) -> dict[str, object]:
        with self.lock:
            row = self.db.execute(
                "SELECT id,status,created,updated,spec,result FROM jobs WHERE tenant=? AND id=?",
                (tenant, identity),
            ).fetchone()
        if not row:
            raise KeyError(identity)
        return {
            "id": row[0],
            "status": row[1],
            "created": row[2],
            "updated": row[3],
            "spec": json.loads(row[4]),
            "result": json.loads(row[5]),
        }

    def list(self, tenant: str) -> list[dict[str, object]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT id,status,created,updated,spec FROM jobs WHERE tenant=? "
                "ORDER BY created DESC LIMIT 50",
                (tenant,),
            ).fetchall()
        return [
            {
                **dict(zip(("id", "status", "created", "updated"), row[:4], strict=True)),
                "title": json.loads(row[4]).get("title", ""),
                "kind": json.loads(row[4]).get("kind", "agent"),
            }
            for row in rows
        ]

    def update(self, tenant: str, identity: str, status: str, result: dict[str, object]) -> bool:
        if status not in (*TERMINAL, "running"):
            raise ValueError("unknown job status")
        encoded = json.dumps(result)
        if len(encoded.encode()) > 2_000_000:
            raise ValueError("job result too large")
        with self.lock, self.db:
            cursor = self.db.execute(
                "UPDATE jobs SET status=?,updated=?,result=? WHERE tenant=? "
                "AND id=? AND status IN ('queued','running')",
                (status, time.time(), encoded, tenant, identity),
            )
        return cursor.rowcount == 1

    def cancel(self, tenant: str, identity: str) -> dict[str, object]:
        job = self.get(tenant, identity)
        if job["status"] not in TERMINAL:
            self.update(
                tenant, identity, "cancelled", {**job["result"], "reason": "operator cancelled"}
            )
            task = self.tasks.get(identity)
            if task:
                task.cancel()
        return self.get(tenant, identity)

    def launch(
        self,
        tenant: str,
        identity: str,
        work: Callable[
            [Callable[[dict[str, object]], Awaitable[None]]], Awaitable[dict[str, object]]
        ],
    ) -> None:
        async def runner():
            try:
                async with self.slot:
                    if not self.update(tenant, identity, "running", {"completed_runs": 0}):
                        return

                    async def progress(value: dict[str, object]) -> None:
                        if not self.update(tenant, identity, "running", value):
                            raise asyncio.CancelledError

                    result = await asyncio.wait_for(work(progress), timeout=600)
                    self.update(tenant, identity, "completed", result)
            except asyncio.CancelledError:
                partial = self.get(tenant, identity)["result"]
                self.update(
                    tenant, identity, "interrupted", {**partial, "reason": "worker stopped"}
                )
                raise
            except Exception:
                partial = self.get(tenant, identity)["result"]
                self.update(
                    tenant, identity, "failed", {**partial, "error_code": "job_execution_failed"}
                )
            finally:
                self.tasks.pop(identity, None)

        self.tasks[identity] = asyncio.create_task(runner())
        self.tasks[identity].add_done_callback(lambda task: self.tasks.pop(identity, None))

    async def close(self) -> None:
        pending = list(self.tasks.values())
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        self.db.close()
