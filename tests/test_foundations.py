from agents.mock import AGENTS, CANARY, run_vulnerable
from lab.corpus import CATEGORIES, generate, load


def test_versioned_corpus_matches_generator():
    assert load() == generate()
    assert len(load()) >= 150
    assert len({a.id for a in load()}) == len(load())
    assert {a.category for a in load()} == set(CATEGORIES)


def test_every_baseline_oracle_checks_actual_effects():
    for agent in AGENTS:
        for attack in load():
            result = run_vulnerable(agent, "\n".join(attack.turns) or attack.payload)
            assert attack.oracle.succeeds(result), (agent, attack.id)
            assert not attack.oracle.succeeds(run_vulnerable(agent, "benign document"))


def test_end_to_end_mock_exfiltration():
    attack = next(a for a in load() if a.category == "exfil-email")
    result = run_vulnerable("email-calendar", attack.payload)
    assert result.effects[0].content == CANARY
    assert result.effects[0].destination.endswith(".invalid/ingest")
