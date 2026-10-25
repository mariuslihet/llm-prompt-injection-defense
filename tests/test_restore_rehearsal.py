import sqlite3

import pytest

from deploy.rehearse import rehearse
from packages.review import ReviewQueue
from packages.storage import State


def test_rehearsal_preserves_sources_and_refuses_overwrite(tmp_path):
    control, audit = tmp_path / "control.sqlite", tmp_path / "audit.sqlite"
    for path in (control, audit):
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE evidence (value TEXT)")
            db.execute("INSERT INTO evidence VALUES ('sample')")
    before = control.read_bytes(), audit.read_bytes()
    destination = tmp_path / "restore"
    result = rehearse(control, audit, destination)
    assert all(item["validated"] for item in result["databases"].values())
    assert result["databases"]["control"]["tables"]["evidence"] == 1
    assert before == (control.read_bytes(), audit.read_bytes())
    with pytest.raises(ValueError, match="fresh directory"):
        rehearse(control, audit, destination)


def test_review_restart_does_not_retry_claimed_effect(tmp_path):
    path = str(tmp_path / "control.sqlite")
    state = State(path)
    reviews = ReviewQueue(state)
    proposal = reviews.create("tenant", "policy", {"arguments": {"body": "sample"}})
    reviews.claim("tenant", proposal["id"], "policy", True)
    state.db.close()
    recovered = State(path)
    queue = ReviewQueue(recovered)
    assert queue.get("tenant", proposal["id"])["status"] == "interrupted"
    with pytest.raises(ValueError, match="no longer pending"):
        queue.claim("tenant", proposal["id"], "policy", True)
    recovered.db.close()
