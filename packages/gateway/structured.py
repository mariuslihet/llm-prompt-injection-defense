"""Strict bounded JSON transport, accepting only a whole-object Markdown wrapper."""


def json_text(text: str) -> str:
    if len(text) > 16384:
        raise ValueError("model output too large")
    stripped = text.strip()
    for fence in ("```json\n", "```\n"):
        if stripped.startswith(fence) and stripped.endswith("```"):
            return stripped[len(fence) : -3].strip()
    return stripped
