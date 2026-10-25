"""Durable human review state machine. Effects are simulated and never retried."""

import json
import time
import uuid

from packages.storage import State


class ReviewQueue:
    def __init__(self, state: State):
        self.state = state
        with state.lock, state.db:
            state.db.execute(
                "CREATE TABLE IF NOT EXISTS action_reviews ("
                "id TEXT PRIMARY KEY, tenant TEXT NOT NULL, policy TEXT NOT NULL, "
                "body TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, "
                "status TEXT NOT NULL, result TEXT NOT NULL)"
            )
            state.db.execute(
                "CREATE TABLE IF NOT EXISTS review_events ("
                "id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, review_id TEXT NOT NULL, "
                "at REAL NOT NULL, kind TEXT NOT NULL, note TEXT NOT NULL, actor TEXT NOT NULL)"
            )
            state.db.execute(
                "INSERT INTO review_events (tenant,review_id,at,kind,note,actor) "
                "SELECT tenant,id,?,'interrupted','Worker stopped; execution will not retry',"
                "'system' FROM action_reviews WHERE status='executing'",
                (time.time(),),
            )
            state.db.execute(
                "UPDATE action_reviews SET status='interrupted' WHERE status='executing'"
            )

    def create(self, tenant: str, policy: str, body: dict, actor: str = "operator") -> dict:
        identity, now = uuid.uuid4().hex, time.time()
        with self.state.lock, self.state.db:
            if (
                self.state.db.execute(
                    "SELECT COUNT(*) FROM action_reviews WHERE tenant=?", (tenant,)
                ).fetchone()[0]
                >= 1000
            ):
                raise ValueError("review capacity reached")
            self.state.db.execute(
                "INSERT INTO action_reviews VALUES (?,?,?,?,?,?,'pending','{}')",
                (identity, tenant, policy, json.dumps(body), now, now + 300),
            )
            self._event(tenant, identity, "submitted", "Awaiting human decision", actor)
        return self.get(tenant, identity)

    def get(self, tenant: str, identity: str) -> dict:
        with self.state.lock:
            row = self.state.db.execute(
                "SELECT id,policy,body,created,expires,status,result "
                "FROM action_reviews WHERE tenant=? AND id=?",
                (tenant, identity),
            ).fetchone()
        if row is None:
            raise KeyError(identity)
        with self.state.lock:
            events = self.state.db.execute(
                "SELECT at,kind,note,actor FROM review_events "
                "WHERE tenant=? AND review_id=? ORDER BY id LIMIT 100",
                (tenant, identity),
            ).fetchall()
        return {
            "id": row[0],
            "policy_digest": row[1],
            "proposal": json.loads(row[2]),
            "created": row[3],
            "expires": row[4],
            "status": "expired" if row[5] == "pending" and row[4] <= time.time() else row[5],
            "result": json.loads(row[6]),
            "history": [dict(zip(("at", "kind", "note", "actor"), e, strict=True)) for e in events],
        }

    def list(self, tenant: str) -> list[dict]:
        with self.state.lock:
            ids = self.state.db.execute(
                "SELECT id FROM action_reviews WHERE tenant=? ORDER BY created DESC LIMIT 100",
                (tenant,),
            ).fetchall()
        return [self.get(tenant, row[0]) for row in ids]

    def claim(
        self,
        tenant: str,
        identity: str,
        policy: str,
        approve: bool,
        note: str = "",
        actor: str = "admin",
    ) -> dict:
        with self.state.lock, self.state.db:
            self.state.db.execute("BEGIN IMMEDIATE")
            proposal = self.get(tenant, identity)
            if proposal["status"] != "pending":
                raise ValueError("review is no longer pending")
            if proposal["policy_digest"] != policy:
                raise ValueError("policy changed; submit a new proposal for review")
            self.state.db.execute(
                "UPDATE action_reviews SET status=? WHERE tenant=? AND id=?",
                ("executing" if approve else "denied", tenant, identity),
            )
            self._event(tenant, identity, "approved" if approve else "denied", note, actor)
        return proposal

    def _event(self, tenant: str, identity: str, kind: str, note: str, actor: str) -> None:
        count = self.state.db.execute(
            "SELECT COUNT(*) FROM review_events WHERE tenant=? AND review_id=?", (tenant, identity)
        ).fetchone()[0]
        if count >= 100:
            raise ValueError("review history capacity reached")
        self.state.db.execute(
            "INSERT INTO review_events (tenant,review_id,at,kind,note,actor) VALUES (?,?,?,?,?,?)",
            (tenant, identity, time.time(), kind, note, actor),
        )

    def annotate(self, tenant: str, identity: str, note: str, actor: str) -> dict:
        with self.state.lock, self.state.db:
            self.get(tenant, identity)
            # Reserve capacity for a decision and its execution event.
            if len(self.get(tenant, identity)["history"]) >= 95:
                raise ValueError("review note capacity reached")
            self._event(tenant, identity, "comment", note, actor)
        return self.get(tenant, identity)

    def withdraw(self, tenant: str, identity: str, note: str, actor: str) -> dict:
        with self.state.lock, self.state.db:
            self.state.db.execute("BEGIN IMMEDIATE")
            if self.get(tenant, identity)["status"] != "pending":
                raise ValueError("only pending reviews can be withdrawn")
            self.state.db.execute(
                "UPDATE action_reviews SET status='withdrawn' WHERE tenant=? AND id=?",
                (tenant, identity),
            )
            self._event(tenant, identity, "withdrawn", note, actor)
        return self.get(tenant, identity)

    def finish(self, tenant: str, identity: str, result: dict, failed: bool = False) -> dict:
        with self.state.lock, self.state.db:
            cursor = self.state.db.execute(
                "UPDATE action_reviews SET status=?, result=? "
                "WHERE tenant=? AND id=? AND status='executing'",
                ("failed" if failed else "executed", json.dumps(result), tenant, identity),
            )
            if cursor.rowcount:
                self._event(tenant, identity, "failed" if failed else "executed", "", "system")
        return self.get(tenant, identity)
