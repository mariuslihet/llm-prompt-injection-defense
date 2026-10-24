import hashlib

import pytest

from deploy.backup import backup, restore, validate
from packages.storage import Identity, State
from packages.telemetry import Audit


def test_control_and_audit_backup_restore_are_read_only_and_refuse_overwrite(tmp_path):
    for name in ("control", "audit"):
        source, saved, restored = (
            tmp_path / f"{name}-{suffix}.sqlite" for suffix in ("source", "backup", "restore")
        )
        if name == "control":
            state = State(str(source))
            state.seed("fake", "fake-backup-credential", Identity(role="viewer"))
            state.close()
        else:
            audit = Audit(str(source))
            audit.append("fake", {"action": "allow", "rule": "backup-test"})
            audit.close()
        initial = hashlib.sha256(source.read_bytes()).hexdigest()
        backup(source, saved)
        restore(saved, restored)
        validate(restored)
        assert hashlib.sha256(source.read_bytes()).hexdigest() == initial
        with pytest.raises(ValueError):
            backup(source, saved)
        with pytest.raises(ValueError):
            restore(saved, restored)
