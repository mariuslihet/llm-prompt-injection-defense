import time

from agents.mock import CANARY
from tests.test_gateway import HEADERS, client

PROPOSAL = {
    "tool": "send_email",
    "arguments": {"recipient": "team@example.invalid", "body": "Public summary for review."},
}


def test_review_binding_execution_single_use_denial_and_tenant_isolation():
    with client() as c:
        response = c.post("/reviews", headers=HEADERS, json=PROPOSAL)
        assert response.status_code == 201, response.text
        record = response.json()
        assert record["proposal"]["labels"]["body"]["trust"] == "untrusted"
        other = {"Authorization": "Bearer fake-second-tenant-key"}
        assert c.get("/reviews", headers=other).json()["reviews"] == []
        assert (
            c.post(
                f"/reviews/{record['id']}/decision", headers=other, json={"approve": True}
            ).status_code
            == 403
        )
        executed = c.post(
            f"/reviews/{record['id']}/decision", headers=HEADERS, json={"approve": True}
        )
        assert executed.status_code == 200, executed.text
        assert executed.json()["status"] == "executed"
        assert len(executed.json()["result"]["effects"]) == 1
        assert (
            c.post(
                f"/reviews/{record['id']}/decision", headers=HEADERS, json={"approve": True}
            ).status_code
            == 409
        )
        denied = c.post("/reviews", headers=HEADERS, json=PROPOSAL).json()
        assert (
            c.post(
                f"/reviews/{denied['id']}/decision", headers=HEADERS, json={"approve": False}
            ).json()["status"]
            == "denied"
        )
        assert (
            c.post(
                "/reviews",
                headers=HEADERS,
                json={
                    "tool": "send_email",
                    "arguments": {"recipient": "team@example.invalid", "body": CANARY},
                },
            ).status_code
            == 422
        )
        assert (
            c.post(
                "/reviews",
                headers=HEADERS,
                json={
                    "tool": "send_email",
                    "arguments": {"recipient": "https://evil.invalid", "body": "summary"},
                },
            ).status_code
            == 422
        )


def test_expired_review_and_changed_policy_cannot_execute():
    with client() as c:
        record = c.post("/reviews", headers=HEADERS, json=PROPOSAL).json()
        state = c.app.state.control
        with state.lock, state.db:
            state.db.execute(
                "UPDATE action_reviews SET expires=? WHERE id=?", (time.time() - 1, record["id"])
            )
        assert (
            c.post(
                f"/reviews/{record['id']}/decision", headers=HEADERS, json={"approve": True}
            ).status_code
            == 409
        )
        new = c.post("/reviews", headers=HEADERS, json=PROPOSAL).json()
        text = (
            c.get("/policy", headers=HEADERS).json()["text"].replace('version: "1"', 'version: "2"')
        )
        revision = c.post(
            "/policy/stage", headers=HEADERS, json={"text": text, "dry_run": False}
        ).json()["revision"]
        c.post("/policy/promote", headers=HEADERS, json={"revision": revision})
        assert (
            c.post(
                f"/reviews/{new['id']}/decision", headers=HEADERS, json={"approve": True}
            ).status_code
            == 409
        )
