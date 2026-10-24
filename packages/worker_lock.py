"""OS-released exclusive worker lock for a production SQLite state directory."""

import os
from pathlib import Path
from typing import BinaryIO


class WorkerLock:
    def __init__(self, database: str) -> None:
        target = Path(database).resolve().with_suffix(".worker.lock")
        target.parent.mkdir(parents=True, exist_ok=True)
        self.handle: BinaryIO = target.open("a+b")
        try:
            if target.stat().st_size == 0:
                self.handle.write(b"0")
                self.handle.flush()
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.handle.close()
            raise RuntimeError("another worker owns this SQLite state directory") from exc

    def close(self) -> None:
        self.handle.close()
