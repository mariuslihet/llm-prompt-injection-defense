"""Consistent SQLite backup/restore with chain validation; server must be stopped to restore."""

import argparse
import shutil
import sqlite3
from pathlib import Path

from packages.telemetry import Audit


def backup(source: Path, destination: Path) -> None:
    if not source.is_file() or destination.exists() or source.resolve() == destination.resolve():
        raise ValueError("existing source and fresh destination required")
    with sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True) as src:
        with sqlite3.connect(destination) as dst:
            src.backup(dst)
    audit = Audit(str(destination))
    try:
        if not audit.verify():
            raise ValueError("backup audit chain is invalid")
    finally:
        audit.close()


def restore(source: Path, destination: Path) -> None:
    if not source.is_file() or destination.exists():
        raise ValueError("restore only into a fresh path; preserve existing evidence")
    audit = Audit(str(source))
    try:
        if not audit.verify():
            raise ValueError("source audit chain is invalid")
    finally:
        audit.close()
    shutil.copyfile(source, destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("backup", "restore"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    (backup if args.action == "backup" else restore)(args.source, args.destination)
