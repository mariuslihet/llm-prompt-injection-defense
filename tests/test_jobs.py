import asyncio

import pytest

from lab.campaigns import RunSpec
from packages.jobs import JobCapacity, JobConflict, Jobs
from tests.test_email_agent import ScriptedProvider
from tests.test_gateway import HEADERS, client


def test_job_idempotency_quota_restart_and_tenant_isolation(tmp_path):
    path = str(tmp_path / "jobs.sqlite")
    jobs = Jobs(path)
    identity, created = jobs.create("alice", RunSpec(), "request01")
    assert created and jobs.create("alice", RunSpec(), "request01") == (identity, False)
    with pytest.raises(JobConflict):
        jobs.create("alice", RunSpec(email="different"), "request01")
    with pytest.raises(KeyError):
        jobs.get("bob", identity)
    assert not jobs.list("bob")
    jobs.create("alice", RunSpec(), "request02")
    with pytest.raises(JobCapacity):
        jobs.create("alice", RunSpec(), "request03")
    jobs.db.close()
    restarted = Jobs(path)
    assert restarted.get("alice", identity)["status"] == "interrupted"
    assert not restarted.update("alice", identity, "completed", {"late": True})
    restarted.db.close()


@pytest.mark.anyio
async def test_cancelled_job_cannot_publish_a_late_result():
    jobs = Jobs()
    identity, _ = jobs.create("alice", RunSpec(), "request01")
    running = asyncio.Event()

    async def work(progress):
        await progress({"records": [{"case": "completed fake case"}]})
        running.set()
        await asyncio.Event().wait()

    jobs.launch("alice", identity, work)
    await running.wait()
    assert jobs.cancel("alice", identity)["status"] == "cancelled"
    assert jobs.get("alice", identity)["result"]["records"]
    await jobs.close()


def test_authenticated_job_api_results_and_roles():
    with client(agent_provider=ScriptedProvider()) as c:
        assert c.get("/lab/config").status_code == 401
        assert c.get("/lab/config", headers=HEADERS).json()["enabled"]
        assert c.get("/ready").json()["status"] == "ready"
        assert c.get("/ready").headers["x-content-type-options"] == "nosniff"
        assert c.post("/lab/jobs", headers=HEADERS, json={}).status_code == 422
        headers = {**HEADERS, "Idempotency-Key": "local-request-01"}
        response = c.post("/lab/jobs", headers=headers, json={"defense": "none"})
        assert response.status_code == 202
        identity = response.json()["id"]
        for _ in range(30):
            result = c.get("/lab/jobs/" + identity, headers=HEADERS).json()
            if result["status"] == "completed":
                break
        assert result["status"] == "completed"
        assert result["result"]["records"][0]["run"]["attack_success"]
        assert (
            c.post("/lab/jobs", headers=headers, json={"defense": "none"}).json()["id"] == identity
        )
        assert c.post("/lab/jobs", headers=headers, json={}).status_code == 409
        other = {"Authorization": "Bearer fake-second-tenant-key"}
        assert c.get("/lab/jobs/" + identity, headers=other).status_code == 404
        assert not c.get("/lab/jobs", headers=other).json()["jobs"]
    with client(role="viewer", agent_provider=ScriptedProvider()) as c:
        assert c.post("/lab/jobs", headers=headers, json={}).status_code == 403
    with client() as c:
        assert c.post("/lab/jobs", headers=headers, json={}).status_code == 503


def test_production_rejects_demo_credentials_and_ephemeral_state(monkeypatch):
    monkeypatch.setenv("MECHA_ENV", "production")
    with pytest.raises(ValueError, match="durable"):
        client()


def test_built_console_and_api_share_one_origin_without_development_proxy(tmp_path, monkeypatch):
    (tmp_path / "index.html").write_text("<h1>Local console</h1>", encoding="utf-8")
    monkeypatch.setenv("MECHA_DASHBOARD_PATH", str(tmp_path))
    with client() as c:
        assert "Local console" in c.get("/").text
        assert c.get("/api/health").json()["status"] == "ok"
        assert c.get("/api/lab/config", headers=HEADERS).status_code == 200


def test_exclusive_worker_lock_releases_for_restart(tmp_path):
    from packages.worker_lock import WorkerLock

    path = str(tmp_path / "control.sqlite")
    first = WorkerLock(path)
    with pytest.raises(RuntimeError, match="another worker"):
        WorkerLock(path)
    first.close()
    second = WorkerLock(path)
    second.close()


@pytest.mark.anyio
async def test_slow_request_body_expires_without_invoking_application():
    from packages.gateway.app import BodyLimit

    async def application(scope, receive, send):
        raise AssertionError("body timeout must stop before application")

    async def receive():
        await asyncio.Event().wait()

    messages = []

    async def send(message):
        messages.append(message)

    await BodyLimit(application, timeout_seconds=0.001)({"type": "http"}, receive, send)
    assert messages[0]["status"] == 408


def test_audit_failure_does_not_launch_or_strand_a_queued_model_job():
    from packages.telemetry import Audit

    class FailedAudit(Audit):
        def append(self, *args, **kwargs):
            raise RuntimeError("fake audit failure")

    with client(agent_provider=ScriptedProvider(), audit=FailedAudit()) as c:
        headers = {**HEADERS, "Idempotency-Key": "audit-failure-test"}
        response = c.post("/lab/jobs", headers=headers, json={})
        assert response.status_code == 503
        assert c.get("/lab/jobs", headers=HEADERS).json()["jobs"][0]["status"] == "failed"
