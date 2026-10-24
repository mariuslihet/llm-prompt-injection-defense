"""Safe local CTF with tenant-scoped, durable fake-data review records."""

import hashlib
import sqlite3
import threading
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agents.mock import AGENTS, command
from eval.harness import defend
from lab.corpus import load

LEVELS = ("none", "detector", "detector-sanitizer", "full-ifc")


class Submission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    player: str = Field(pattern=r"^[a-zA-Z0-9_-]{3,24}$")
    level: int = Field(ge=0, le=3)
    attack_id: str = Field(max_length=100)
    payload: str = Field(max_length=16384)
    agent: str = Field(default=AGENTS[0], pattern="^(email-calendar|rag|web-research)$")


class Arena:
    def __init__(self, path: str = ":memory:") -> None:
        self.attacks = {a.id: a for a in load()}
        self.lock = threading.Lock()
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS solves (tenant TEXT, player TEXT, level INTEGER, "
            "PRIMARY KEY(tenant,player,level))"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS arena_review (tenant TEXT, digest TEXT, "
            "submission TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY(tenant,digest))"
        )

    def _submissions(self, status: str) -> dict[tuple[str, str], Submission]:
        with self.lock:
            rows = self.db.execute(
                "SELECT tenant,digest,submission FROM arena_review WHERE status=?", (status,)
            ).fetchall()
        return {
            (tenant, digest): Submission.model_validate_json(record)
            for tenant, digest, record in rows
        }

    @property
    def pending(self) -> dict[tuple[str, str], Submission]:
        return self._submissions("pending")

    @property
    def reviewed(self) -> dict[tuple[str, str], Submission]:
        return self._submissions("reviewed")

    def submit(self, tenant: str, body: Submission) -> dict[str, object]:
        attack = self.attacks.get(body.attack_id)
        if attack is None or command(body.payload) != command(attack.payload):
            raise ValueError("use a mutation of the selected fake-data fixture")
        result = defend(body.agent, body.payload, LEVELS[body.level])
        success = attack.oracle.succeeds(result)
        digest = hashlib.sha256(body.payload.encode()).hexdigest()
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if success:
                queued = self.db.execute(
                    "SELECT COUNT(*) FROM arena_review WHERE tenant=? AND status='pending'",
                    (tenant,),
                ).fetchone()[0]
                existing = self.db.execute(
                    "SELECT 1 FROM arena_review WHERE tenant=? AND digest=?", (tenant, digest)
                ).fetchone()
                if queued >= 1000 and not existing:
                    raise ValueError("review queue capacity reached")
                self.db.execute(
                    "INSERT OR IGNORE INTO solves VALUES (?,?,?)", (tenant, body.player, body.level)
                )
                self.db.execute(
                    "INSERT OR IGNORE INTO arena_review VALUES (?,?,?,'pending')",
                    (tenant, digest, body.model_dump_json()),
                )
        return {
            "success": success,
            "digest": digest,
            "decisions": result.decisions,
            "simulated": True,
            "review_required": success,
        }

    def review(self, tenant: str, digest: str) -> None:
        with self.lock, self.db:
            cursor = self.db.execute(
                "UPDATE arena_review SET status='reviewed' "
                "WHERE tenant=? AND digest=? AND status='pending'",
                (tenant, digest),
            )
            if cursor.rowcount != 1:
                raise KeyError(digest)

    def candidates(self, tenant: str, status: str = "reviewed") -> list[dict[str, object]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT digest,submission FROM arena_review "
                "WHERE tenant=? AND status=? ORDER BY digest LIMIT 1000",
                (tenant, status),
            ).fetchall()
        return [
            {"digest": digest, **Submission.model_validate_json(record).model_dump()}
            for digest, record in rows
        ]

    def leaderboard(self, tenant: str) -> list[dict[str, object]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT player,COUNT(*) FROM solves WHERE tenant=? GROUP BY player "
                "ORDER BY COUNT(*) DESC,player LIMIT 100",
                (tenant,),
            ).fetchall()
        return [{"player": player, "levels_solved": count} for player, count in rows]
