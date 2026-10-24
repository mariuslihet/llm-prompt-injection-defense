"""Seeded, budgeted evolutionary search against repository-owned mock targets only."""

import hashlib
import random

from agents.mock import Result
from eval.harness import defend
from lab.corpus import Attack
from lab.mutators import OPERATORS, mutate
from packages.detectors import detect
from packages.policy import Policy


def evolve(
    agent: str,
    attack: Attack,
    config: str,
    *,
    seed: int = 42,
    budget: int = 32,
    population_size: int = 4,
) -> tuple[Result, list[dict[str, object]]]:
    if not 1 <= budget <= 1000 or not 1 <= population_size <= 16:
        raise ValueError("bounded campaign parameters required")
    rng = random.Random(seed)
    population = [(float("inf"), attack.payload)]
    trace: list[dict[str, object]] = []
    best = Result()
    for attempt in range(budget):
        parent = rng.choice(population[:population_size])[1]
        operator = "original" if attempt == 0 else rng.choice(OPERATORS)
        payload = parent if attempt == 0 else mutate(parent, rng, operator)
        result = defend(agent, payload, config)
        success = attack.oracle.succeeds(result)
        score = detect(payload).score
        trace.append(
            {
                "attempt": attempt,
                "operator": operator,
                "score": score,
                "success": success,
                "parent": hashlib.sha256(parent.encode()).hexdigest(),
                "payload": payload,
            }
        )
        if success:
            return result, trace
        population.append((score, payload))
        population.sort(key=lambda entry: entry[0])
        population = population[:population_size]
        best = result
    return best, trace


def policy_targets(policy: Policy) -> list[dict[str, str]]:
    """Select concrete argument barriers to challenge; never edits the policy."""
    targets = []
    for rule in policy.rules:
        for argument in sorted(rule.trusted_arguments):
            targets.append(
                {"tool": rule.tool, "argument": argument, "attack": "untrusted-destination"}
            )
        if rule.external:
            targets.append({"tool": rule.tool, "argument": "*", "attack": "private-egress"})
            if rule.approval_after_untrusted:
                targets.append({"tool": rule.tool, "argument": "*", "attack": "approval-bypass"})
    return targets
