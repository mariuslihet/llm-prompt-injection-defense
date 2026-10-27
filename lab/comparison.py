"""Descriptive regression checks for matching completed evaluation datasets."""

from collections import Counter


def _adaptive_inputs(result: dict, defense: str) -> Counter:
    """Identify actual generated inputs, not merely their generating configuration."""
    return Counter(
        (r.get("case_id"), r.get("round"), r.get("payload_sha256"))
        for r in result.get("records", [])
        if r.get("case") == "adaptive" and r.get("run", {}).get("defense") == defense
    )


def compare(current: dict, baseline: dict) -> dict:
    if current["status"] != "completed" or baseline["status"] != "completed":
        raise ValueError("both runs must be completed")
    now, before = current["result"], baseline["result"]
    if not now.get("dataset_digest") or now["dataset_digest"] != before.get("dataset_digest"):
        raise ValueError("runs use different evaluation inputs or budgets; rerun a matching suite")
    rows = []
    for row in now["summary"]:
        old = next((r for r in before["summary"] if r["defense"] == row["defense"]), None)
        if old is None:
            raise ValueError("defense configurations do not match")
        if now.get("spec", {}).get("adaptive_rounds", 0) or before.get("spec", {}).get(
            "adaptive_rounds", 0
        ):
            actual, previous = (
                _adaptive_inputs(now, row["defense"]),
                _adaptive_inputs(before, row["defense"]),
            )
            if (
                not actual
                or not previous
                or actual != previous
                or any(
                    not case_id or round_number is None or not payload
                    for case_id, round_number, payload in actual
                )
            ):
                raise ValueError(
                    "adaptive attack inputs differ or are missing; replay the same payloads "
                    "before comparing results"
                )
        attack_delta = row["attack_successes"] - old["attack_successes"]
        utility_delta = row["benign_successes"] - old["benign_successes"]
        valid = row["conclusive"] and old["conclusive"]
        rows.append(
            {
                "defense": row["defense"],
                "attack_delta": attack_delta,
                "utility_delta": utility_delta,
                "p95_delta_ms": round(row["p95_ms"] - old["p95_ms"], 3)
                if row.get("p95_ms") is not None and old.get("p95_ms") is not None
                else None,
                "status": "inconclusive"
                if not valid
                else "regression"
                if attack_delta > 0 or utility_delta < 0
                else "improvement"
                if attack_delta < 0 or utility_delta > 0
                else "unchanged",
            }
        )
    return {
        "current": current["id"],
        "baseline": baseline["id"],
        "rows": rows,
        "model_changed": now.get("model") != before.get("model"),
        "policy_changed": now.get("policy_digest") != before.get("policy_digest"),
        "grounding_changed": now.get("spec", {}).get("grounding", "off")
        != before.get("spec", {}).get("grounding", "off"),
        "recovery_changed": now.get("spec", {}).get("recover_model_errors", False)
        != before.get("spec", {}).get("recover_model_errors", False),
        "note": "Descriptive count changes on matching inputs. Small-sample differences "
        "and latency changes are not statistical significance tests.",
    }
