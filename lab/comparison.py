"""Descriptive regression checks for matching completed evaluation datasets."""


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
        attack_delta = row["attack_successes"] - old["attack_successes"]
        utility_delta = row["benign_successes"] - old["benign_successes"]
        valid = row["conclusive"] and old["conclusive"]
        rows.append(
            {
                "defense": row["defense"],
                "attack_delta": attack_delta,
                "utility_delta": utility_delta,
                "p95_delta_ms": round(row["p95_ms"] - old["p95_ms"], 3),
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
