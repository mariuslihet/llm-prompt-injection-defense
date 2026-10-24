"""Download pinned official local inference artifacts; verify before extraction."""

import hashlib
import json
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "local-inference"
REVISION = "bb5d59e06d9551d752d08b292a50eb208b07ab1f"
RELEASE = "b11853"
FILES = {
    "llama-b11853-bin-win-cuda-12.4-x64.zip": (
        "913c33b9128fe0b0aaf35e4a4143a38baaaa39ca35903b36953e9e1901e81705"
    ),
    "cudart-llama-bin-win-cuda-12.4-x64.zip": (
        "8c79a9b226de4b3cacfd1f83d24f962d0773be79f1e7b75c6af4ded7e32ae1d6"
    ),
    "qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf": (
        "dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db"
    ),
    "qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf": (
        "539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a"
    ),
}


def acquire(item: tuple[str, str]) -> dict[str, str]:
    name, expected = item
    url = (
        f"https://github.com/ggml-org/llama.cpp/releases/download/{RELEASE}/{name}"
        if name.endswith(".zip")
        else f"https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/{REVISION}/{name}"
    )
    path = ROOT / name
    if not path.exists():
        partial = path.with_suffix(path.suffix + ".partial")
        print(f"Downloading {name}", flush=True)
        # URLs above are fixed official HTTPS assets, never supplied by a request.
        with urllib.request.urlopen(url, timeout=120) as response, partial.open("wb") as out:  # noqa: S310
            while chunk := response.read(4 * 1024 * 1024):
                out.write(chunk)
        partial.replace(path)
    with path.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected:
        raise ValueError(f"Checksum mismatch: {name}")
    print(f"Verified {name}", flush=True)
    if name.endswith(".zip"):
        destination = ROOT / "runtime"
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if (
                    not (destination / member.filename)
                    .resolve()
                    .is_relative_to(destination.resolve())
                ):
                    raise ValueError("Unsafe archive path")
            archive.extractall(destination)
    return {"file": name, "sha256": actual, "url": url}


if __name__ == "__main__":
    ROOT.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        files = list(pool.map(acquire, FILES.items()))
    (ROOT / "manifest.json").write_text(
        json.dumps(
            {
                "model": "Qwen2.5-7B-Instruct",
                "revision": REVISION,
                "runtime": RELEASE,
                "quantization": "Q4_K_M",
                "files": files,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
