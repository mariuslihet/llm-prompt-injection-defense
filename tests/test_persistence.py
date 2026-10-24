from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from lab.arena import Arena, Submission
from lab.corpus import load
from packages.gateway.app import Tenant, create_app
from packages.storage import Identity, State, StateApprovals
from tests.test_gateway import HEADERS, KEY, client


def test_hashed_credentials_grants_and_limits_survive_restart(tmp_path):
    path = str(tmp_path / "state.sqlite")
    state = State(path)
    state.seed("alice", KEY, Identity(role="admin"))
    dynamic_key = state.create_tenant("new", "viewer")
    grant = StateApprovals(state).issue("fake-binding")
    assert state.allow_request("alice", 1)
    state.close()
    reopened = State(path)
    assert reopened.authenticate(dynamic_key)[0] == "new"
    assert not reopened.authenticate("wrong")
    assert not reopened.allow_request("alice", 1)
    assert StateApprovals(reopened).consume(grant, "fake-binding")
    assert not StateApprovals(reopened).consume(grant, "fake-binding")
    dump = "\n".join(reopened.db.iterdump())
    assert KEY not in dump and dynamic_key not in dump and grant not in dump
    reopened.close()


def test_grants_are_atomic_across_connections_and_expire(tmp_path, monkeypatch):
    path = str(tmp_path / "grants.sqlite")
    first, second = State(path), State(path)
    token = StateApprovals(first).issue("action")
    with ThreadPoolExecutor(2) as pool:
        results = list(
            pool.map(lambda state: StateApprovals(state).consume(token, "action"), (first, second))
        )
    assert sorted(results) == [False, True]
    monkeypatch.setattr("packages.storage.time.time", lambda: 100.0)
    token = StateApprovals(first).issue("action", ttl=1)
    monkeypatch.setattr("packages.storage.time.time", lambda: 102.0)
    assert not StateApprovals(second).consume(token, "action")
    with pytest.raises(ValueError):
        StateApprovals(first).issue("action", ttl=301)
    first.close()
    second.close()


def test_arena_review_survives_restart_and_remains_tenant_scoped(tmp_path):
    path = str(tmp_path / "arena.sqlite")
    arena = Arena(path)
    attack = load()[0]
    result = arena.submit(
        "alice",
        Submission(player="fake_player", level=0, attack_id=attack.id, payload=attack.payload),
    )
    arena.db.close()
    restarted = Arena(path)
    assert restarted.pending and restarted.leaderboard("alice")
    assert not restarted.candidates("bob", "pending")
    restarted.review("alice", result["digest"])
    restarted.submit(
        "alice",
        Submission(player="fake_player", level=0, attack_id=attack.id, payload=attack.payload),
    )
    assert not restarted.pending and restarted.candidates("alice")


def test_gateway_persists_tenant_and_policy_changes(tmp_path):
    path = str(tmp_path / "gateway.sqlite")
    tenants = {"alice": Tenant(key=KEY, role="admin", platform_admin=True)}
    with TestClient(create_app(tenants=tenants, state_path=path)) as c:
        created = c.post("/tenants", headers=HEADERS, json={"name": "new", "role": "viewer"}).json()
        current = c.get("/policy", headers=HEADERS).json()
        text = current["text"].replace('version: "1"', 'version: "durable"')
        revision = c.post(
            "/policy/stage", headers=HEADERS, json={"text": text, "dry_run": False}
        ).json()["revision"]
        assert (
            c.post("/policy/promote", headers=HEADERS, json={"revision": revision}).status_code
            == 200
        )
    with TestClient(create_app(tenants=tenants, state_path=path)) as c:
        assert c.get("/policy", headers=HEADERS).json()["policy"]["version"] == "durable"
        assert (
            c.get("/audit", headers={"Authorization": "Bearer " + created["key"]}).status_code
            == 200
        )


def test_trace_replay_contains_labels_not_contents_and_is_tenant_scoped():
    with client() as c:
        response = c.post(
            "/ifc/run",
            headers=HEADERS,
            json={"task": "email-summary", "document": "FAKE_SECRET_NEVER_IN_TRACE"},
        ).json()
        assert response["trace"]["effect_count"] == 0
        replay = c.get("/incidents/" + response["incident"], headers=HEADERS)
        assert replay.status_code == 200
        assert "FAKE_SECRET_NEVER_IN_TRACE" not in replay.text
        assert replay.json()["event"]["trace"]["steps"][0]["inputs"][0]["trust"] == "untrusted"
        assert (
            c.get(
                "/incidents/" + response["incident"],
                headers={"Authorization": "Bearer fake-second-tenant-key"},
            ).status_code
            == 404
        )
        metrics = c.get("/metrics", headers=HEADERS).json()
        assert metrics["block_rate"] == 1 and metrics["actions"]["block"] == 1
