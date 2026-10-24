"""Consistent SQLite backup/restore with chain validation; server must be stopped to restore."""

import argparse
import hashlib
import shutil
import sqlite3
from pathlib import Path


def validate(source: Path) -> None:
    with sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True) as db:
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("database integrity check failed")
        has_audit = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit'"
        ).fetchone()
        if has_audit:
            previous = "0" * 64
            for event, parent, digest in db.execute(
                "SELECT event,previous,digest FROM audit ORDER BY id"
            ):
                if (
                    parent != previous
                    or hashlib.sha256((parent + event).encode()).hexdigest() != digest
                ):
                    raise ValueError("audit chain is invalid")
                previous = digest


def backup(source: Path, destination: Path) -> None:
    if not source.is_file() or destination.exists() or source.resolve() == destination.resolve():
        raise ValueError("existing source and fresh destination required")
    validate(source)
    with sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True) as src:
        with sqlite3.connect(destination) as dst:
            src.backup(dst)
    validate(destination)


def restore(source: Path, destination: Path) -> None:
    if not source.is_file() or destination.exists():
        raise ValueError("restore only into a fresh path; preserve existing evidence")
    validate(source)
    shutil.copyfile(source, destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("backup", "restore"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    (backup if args.action == "backup" else restore)(args.source, args.destination)
