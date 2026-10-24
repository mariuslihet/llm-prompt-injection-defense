"""Explainable heuristic cascade and opt-in local classifier.

Scores are heuristic evidence, not calibrated probabilities. A trained model is
loaded only from an explicit local artifact and has no implicit downloads.
"""

import re
import unicodedata
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Detection:
    score: float
    reasons: tuple[str, ...]
    action: str


PATTERNS = (
    (r"ignore.{0,30}(instructions|rules|prior)", "instruction-override"),
    (r"(system:|administrator|override|forward the private)", "authority-claim"),
    (r"(MECHA_FIXTURE:|\$PRIVATE|\$SYSTEM)", "fixture-instruction"),
    (r"(base64|B64\[|1gn0r3)", "encoding"),
    (r"(display\s*:\s*none|visibility\s*:\s*hidden)", "hidden-content"),
)


def detect(
    text: str, mode: Literal["block", "flag", "shadow"] = "block", threshold: float = 0.6
) -> Detection:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
    reasons = tuple(
        name
        for pattern, name in PATTERNS
        if re.search(pattern, normalized, re.IGNORECASE | re.DOTALL)
    )
    score = min(1.0, 0.65 * len(reasons))
    return Detection(score, reasons, mode if score >= threshold else "allow")


class LocalClassifier:
    """Optional Hugging Face text classifier, isolated from the fast path."""

    def __init__(self, path: str) -> None:
        from pathlib import Path

        if not Path(path).is_dir():
            raise ValueError("classifier requires an explicit local artifact directory")
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

        self._pipeline = pipeline(
            "text-classification",
            model=AutoModelForSequenceClassification.from_pretrained(
                path, local_files_only=True, trust_remote_code=False
            ),
            tokenizer=AutoTokenizer.from_pretrained(
                path, local_files_only=True, trust_remote_code=False
            ),
            device=-1,
        )

    def score(self, text: str) -> float:
        result = self._pipeline(text, truncation=True, max_length=512)[0]
        value = float(result["score"])
        return value if result["label"] in {"LABEL_1", "injection"} else 1.0 - value
