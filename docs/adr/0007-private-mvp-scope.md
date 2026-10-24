# ADR 0007: private, single-host MVP and realistic agent evaluation

Date: 2026-10-24. Status: accepted for implementation.

The operator requested a production-grade MVP after finding the fixture arena
too narrow. Earlier decisions keep the repository private and verification local.
The MVP is a single-host, single-worker research service with authenticated
tenant access, durable bounded jobs, observable model-driven sample-tool agents,
and budgeted natural-language adaptive campaigns. Research-only fixtures remain
explicitly separate. Real providers are configured by the operator, never by
client-supplied URLs or credentials. A local Hugging Face model can be used
without external inference. Tests use scripted providers and no network.

The realistic email task has sample inbox content, a sample private project memo,
and a send-email ledger. No runner has a real email, browser, shell or network
tool. The attacker's control is only the incoming document. Strict model action
schemas, bounded turns and closed tool dispatch constrain every run. Full IFC
uses a planner which cannot see document content and quarantined extraction;
model errors are reported as failures, never counted as defense successes.

Background jobs persist status/results and mark unfinished work interrupted on
restart. They do not promise distributed execution or resumable inference.
Production acceptance still requires Linux deployment/isolation checks,
performance gates, representative real-model attack and normal-task-task results,
and review of the release checklist. This ADR does not relabel unfinished
research or unverified deployment as production-ready.
