"""Reproduce the small CPU-budget DPO fixture selection without changing splits."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


def select(source: Path, output: Path) -> str:
    counts: Counter[tuple[str, str]] = Counter()
    selected = []
    for line in source.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        group = (row["split"], row["group"])
        cap = 8 if row["suite"] == "general" else 2
        if counts[group] < cap:
            selected.append(row)
            counts[group] += 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(json.dumps(row) for row in selected) + "\n", encoding="utf-8")
    return hashlib.sha256(output.read_bytes()).hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(select(args.source, args.output))
