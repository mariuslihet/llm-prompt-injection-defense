# Phase 0: offline foundations

Built three deliberately vulnerable instruction-following fixtures: email and
calendar, RAG and web research. All effects go to an in-memory ledger. Expanded
corpus v1 contains 168 records (21 categories x 8 templates), stored in JSONL.
Every record includes its success oracle; multi-turn records include turns.
These are synthetic fixture commands wrapped in varied attack presentations,
not 168 independently validated natural-language jailbreaks.

Measured locally with `python -m pytest tests/test_foundations.py`: 3 passed.
Tests replay every attack on each agent and require exact matching simulated effects.

| Target | Successes / trials | Baseline ASR |
| --- | --- | --- |
| email-calendar | 168 / 168 | 100% |
| rag | 168 / 168 | 100% |
| web-research | 168 / 168 | 100% |

Failure/limitation: all agents share a deterministic vulnerable follower. This
tests plumbing and effect oracles; it does not estimate any real model's ASR.
Markdown/browser effects are simulated, not rendered by an actual browser.
Hosted CI has not run. Next: validate structural boundaries and utility.
