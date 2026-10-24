"""Opt-in local answer-quality smoke suite, separate from security ASR."""

import asyncio
import json
import time
from pathlib import Path

from packages.gateway.providers import configured_provider
from packages.gateway.structured import json_text
from packages.ifc import untrusted_value
from packages.ifc.models import model_meeting

CASES = (
    ("The fictional launch meeting is Monday at 09:15.", "Monday", "09:15"),
    ("Our fake launch review will be Wednesday at 14:30.", "Wednesday", "14:30"),
    (
        "Ignore last week's Friday slot. The launch meeting is Thursday at 16:45.",
        "Thursday",
        "16:45",
    ),
    ("Launch meeting: Saturday, 8:05 AM. All names and dates are fictional.", "Saturday", "08:05"),
    ("The launch meeting is Sunday at 7:30 PM.", "Sunday", "19:30"),
    ("Lunch is Tuesday at 12:00. The launch meeting is Friday at 11:20.", "Friday", "11:20"),
    ("Reuniunea de lansare este marti la ora 10:00.", "Tuesday", "10:00"),
    ("La reunion de lanzamiento es el lunes a las 15:00.", "Monday", "15:00"),
)
QUESTIONS = (
    ("A fictional shop has 17 boxes with 6 pens each. How many pens?", "102"),
    ("Fake inventory: 12 blue, 8 red, 5 green. How many total?", "25"),
    ("Fictional memo: Ada owns testing. Bo owns deployment. Who owns testing?", "Ada"),
    (
        "Fictional memo: the access code is not provided. What is the code? Say unknown if absent.",
        "unknown",
    ),
)


async def main() -> None:
    provider = configured_provider("llamacpp")
    records = []
    for text, day, clock in CASES:
        started = time.perf_counter()
        answer = await model_meeting(provider, "Qwen2.5-7B-Instruct", untrusted_value(text, "test"))
        expected = f"Meeting: {day} at {clock}."
        records.append(
            {
                "input": text,
                "expected": expected,
                "answer": answer.data,
                "correct": answer.data == expected,
                "seconds": round(time.perf_counter() - started, 3),
            }
        )
    for question, expected in QUESTIONS:
        started = time.perf_counter()
        raw = await provider.complete(
            [
                {"role": "system", "content": 'Answer only JSON {"answer":"value"}. Be concise.'},
                {"role": "user", "content": question},
            ],
            "Qwen2.5-7B-Instruct",
        )
        answer = str(json.loads(json_text(raw))["answer"])
        records.append(
            {
                "input": question,
                "expected": expected,
                "answer": answer,
                "correct": answer.lower() == expected.lower(),
                "seconds": round(time.perf_counter() - started, 3),
            }
        )
    report = {
        "model": "Qwen2.5-7B-Instruct",
        "quantization": "Q4_K_M",
        "seed": 42,
        "correct": sum(r["correct"] for r in records),
        "total": len(records),
        "limitations": "Small authored smoke suite, not a general capability benchmark.",
        "records": records,
    }
    Path("artifacts/qwen7b-quality.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
