"""Restore into a new directory; never overwrite or start from restored live state."""

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

from deploy.backup import backup, restore, validate


def inventory(path: Path) -> dict[str, int]:
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        names = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return {
            # SQLite identifiers cannot be bound; quote and escape schema-owned names.
            name: db.execute(
                'SELECT COUNT(*) FROM "' + name.replace('"', '""') + '"'  # noqa: S608
            ).fetchone()[0]
            for (name,) in names
        }


def rehearse(control: Path, audit: Path, destination: Path) -> dict:
    if destination.exists():
        raise ValueError("rehearsal requires a fresh directory")
    if not control.is_file() or not audit.is_file():
        raise ValueError("both source databases must exist")
    destination.mkdir(parents=True)
    results = {}
    for name, source in (("control", control), ("audit", audit)):
        snapshot = destination / f"{name}.backup.sqlite"
        restored = destination / f"{name}.restored.sqlite"
        backup(source, snapshot)
        restore(snapshot, restored)
        validate(restored)
        original_counts, restored_counts = inventory(snapshot), inventory(restored)
        if original_counts != restored_counts or snapshot.read_bytes() != restored.read_bytes():
            raise ValueError("restore differs from snapshot")
        results[name] = {
            "tables": restored_counts,
            "sha256": hashlib.sha256(restored.read_bytes()).hexdigest(),
            "validated": True,
        }
    report = {
        "databases": results,
        "scope": "SQLite integrity, audit chain and byte-identical restore into fresh paths",
        "limitations": (
            "Separate database snapshots are not a cross-database transaction. "
            "No service cutover, production disaster recovery or secret rotation was exercised."
        ),
    }
    (destination / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--control", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.control, args.audit, args.destination)))
