"""Explicit, pinned public-model acquisition; never called by tests or training."""

import argparse
import hashlib
import json
import re
from pathlib import Path


def acquire(repo: str, revision: str, directory: Path) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or directory.exists():
        raise ValueError("full immutable revision and fresh artifact directory required")
    from huggingface_hub import snapshot_download

    snapshot_download(
        repo_id=repo,
        revision=revision,
        local_dir=directory,
        token=False,
        allow_patterns=[
            "config.json",
            "model.safetensors",
            "vocab.txt",
            "tokenizer.json",
            "tokenizer_config.json",
            "special_tokens_map.json",
            "README.md",
        ],
    )
    manifest = {
        "repo": repo,
        "revision": revision,
        "files": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(directory.iterdir())
            if path.is_file()
        },
    }
    (directory / "mecha-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("repo")
    parser.add_argument("revision")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    acquire(args.repo, args.revision, args.output)
