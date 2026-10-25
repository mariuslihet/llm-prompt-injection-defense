from concurrent.futures import ThreadPoolExecutor

import pytest

from lab.campaigns import RunSpec, execute
from packages.review import ReviewQueue
from packages.storage import State
from tests.test_email_agent import POLICY, ScriptedProvider
from tests.test_gateway import HEADERS, client
from tests.test_review_queue import PROPOSAL


def test_review_metadata_comments_withdrawal_roles_and_history():
    with client() as c:
        response = c.post(
            "/reviews",
            headers=HEADERS,
            json={
                **PROPOSAL,
                "title": "Invoice summary",
                "priority": "urgent",
                "justification": "Accounting review",
            },
        )
        assert response.status_code == 201
        review = response.json()
        assert review["history"][0]["kind"] == "submitted"
        assert review["history"][0]["actor"] == "admin"
        assert review["proposal"]["priority"] == "urgent"
        path = f"/reviews/{review['id']}"
        other = {"Authorization": "Bearer fake-second-tenant-key"}
        assert (
            c.post(path + "/notes", headers=other, json={"note": "Cross-tenant"}).status_code == 404
        )
        assert c.post(path + "/notes", headers=HEADERS, json={"note": " "}).status_code == 422
        assert (
            c.post(path + "/notes", headers=HEADERS, json={"note": "Checked source"}).status_code
            == 200
        )
        withdrawn = c.post(
            path + "/withdraw", headers=HEADERS, json={"note": "Revise content"}
        ).json()
        assert withdrawn["status"] == "withdrawn"
        assert [e["kind"] for e in withdrawn["history"]] == ["submitted", "comment", "withdrawn"]
        assert (
            c.post(path + "/decision", headers=HEADERS, json={"approve": True}).status_code == 409
        )
        assert (
            c.post("/reviews", headers=HEADERS, json={**PROPOSAL, "priority": "bypass"}).status_code
            == 422
        )
        assert (
            c.post("/reviews", headers=HEADERS, json={**PROPOSAL, "labels": {}}).status_code == 422
        )
    with client(role="viewer") as c:
        assert c.get("/reviews", headers=HEADERS).json()["role"] == "viewer"
        assert (
            c.post("/reviews/unknown/notes", headers=HEADERS, json={"note": "note"}).status_code
            == 403
        )


def test_review_decision_note_persists_after_execution_and_restart(tmp_path):
    state = State(str(tmp_path / "control.sqlite"))
    queue = ReviewQueue(state)
    row = queue.create("a", "digest", {})
    queue.claim("a", row["id"], "digest", True, "Reviewed against source")
    queue.finish("a", row["id"], {"simulated": True})
    state.db.close()
    restarted = State(str(tmp_path / "control.sqlite"))
    row = ReviewQueue(restarted).get("a", row["id"])
    assert row["status"] == "executed"
    assert [e["kind"] for e in row["history"]] == ["submitted", "approved", "executed"]
    assert row["history"][1]["note"] == "Reviewed against source"
    restarted.db.close()


def test_concurrent_withdraw_and_approve_have_only_one_winner():
    state = State()
    queue = ReviewQueue(state)
    row = queue.create("a", "policy", {})

    def decide(approve):
        try:
            if approve:
                queue.claim("a", row["id"], "policy", True)
            else:
                queue.withdraw("a", row["id"], "Cancelled", "operator")
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(decide, [True, False])) == 1
    assert len(queue.get("a", row["id"])["history"]) == 2
    state.db.close()


@pytest.mark.anyio
async def test_selected_defenses_control_execution_budget_and_fingerprint():
    async def progress(value):
        pass

    spec = RunSpec(
        kind="suite", adaptive_rounds=0, selected_defenses=("full-ifc",), title="Focused"
    )
    result = await execute(spec, ScriptedProvider(), "script", POLICY, "a", progress)
    assert len(result["records"]) == 6
    assert [r["defense"] for r in result["summary"]] == ["full-ifc"]
    assert "36 shared calls" in result["limits"]
    renamed = await execute(
        spec.model_copy(update={"title": "Renamed"}),
        ScriptedProvider(),
        "script",
        POLICY,
        "a",
        progress,
    )
    assert renamed["dataset_digest"] == result["dataset_digest"]
    different = await execute(
        spec.model_copy(update={"selected_defenses": ("none",)}),
        ScriptedProvider(),
        "script",
        POLICY,
        "a",
        progress,
    )
    assert different["dataset_digest"] != result["dataset_digest"]
    for selection in ((), ("none", "none"), ("unknown",)):
        with pytest.raises(ValueError):
            RunSpec(selected_defenses=selection)


def test_named_job_history_and_original_spec_are_tenant_scoped():
    with client(agent_provider=ScriptedProvider()) as c:
        response = c.post(
            "/lab/jobs",
            headers={**HEADERS, "Idempotency-Key": "named-run-request"},
            json={"title": "Morning regression", "defense": "none"},
        )
        assert response.status_code == 202
        identity = response.json()["id"]
        assert (
            c.get("/lab/jobs", headers=HEADERS).json()["jobs"][0]["title"] == "Morning regression"
        )
        assert (
            c.get(f"/lab/jobs/{identity}", headers=HEADERS).json()["spec"]["title"]
            == "Morning regression"
        )
        other = {"Authorization": "Bearer fake-second-tenant-key"}
        assert c.get("/lab/jobs", headers=other).json()["jobs"] == []
