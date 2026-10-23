"""Safe local CTF with transient payloads and metadata-only leaderboard."""

import hashlib
import sqlite3
import threading

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
    def __init__(self) -> None:
        self.attacks = {a.id: a for a in load()}
        self.lock = threading.Lock()
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.execute(
            "CREATE TABLE solves (tenant TEXT, player TEXT, level INTEGER, "
            "PRIMARY KEY(tenant,player,level))"
        )
        # Payloads are transient; they are not logs and are never sent to third parties.
        self.pending: dict[tuple[str, str], Submission] = {}
        self.reviewed: dict[tuple[str, str], Submission] = {}

    def submit(self, tenant: str, body: Submission) -> dict[str, object]:
        attack = self.attacks.get(body.attack_id)
        if attack is None or command(body.payload) != command(attack.payload):
            raise ValueError("use a mutation of the selected fake-data fixture")
        result = defend(body.agent, body.payload, LEVELS[body.level])
        success = attack.oracle.succeeds(result)
        digest = hashlib.sha256(body.payload.encode()).hexdigest()
        with self.lock, self.db:
            if success:
                self.db.execute(
                    "INSERT OR IGNORE INTO solves VALUES (?,?,?)", (tenant, body.player, body.level)
                )
                if len(self.pending) >= 1000:
                    raise ValueError("review queue capacity reached")
                self.pending[(tenant, digest)] = body
        return {
            "success": success,
            "digest": digest,
            "decisions": result.decisions,
            "simulated": True,
            "review_required": success,
        }

    def review(self, tenant: str, digest: str) -> None:
        with self.lock:
            body = self.pending.pop((tenant, digest))
            self.reviewed[(tenant, digest)] = body

    def leaderboard(self, tenant: str) -> list[dict[str, object]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT player,COUNT(*) FROM solves WHERE tenant=? GROUP BY player "
                "ORDER BY COUNT(*) DESC,player LIMIT 100",
                (tenant,),
            ).fetchall()
        return [{"player": player, "levels_solved": count} for player, count in rows]
