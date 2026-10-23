"""SIEM exports and opt-in webhook notifications; only metadata is accepted."""

import json
import os

import httpx

from packages.policy import allowed_url


def cef(event: dict[str, str]) -> str:
    def escape(value: str) -> str:
        return (
            value.replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("=", "\\=")
            .replace("\n", " ")
            .replace("\r", " ")
        )

    return "CEF:0|Mecha|Gateway|0.1|policy|Security decision|5|" + " ".join(
        f"{k}={escape(event[k])}" for k in ("action", "rule", "request_id") if k in event
    )


async def webhook(
    url: str, event: dict[str, str], *, kind: str, hosts: frozenset[str], routing_key: str = ""
) -> None:
    if os.getenv("MECHA_ALLOW_WEBHOOKS") != "1" or not allowed_url(url, hosts):
        raise ValueError("webhook destination denied")
    if set(event) - {"action", "rule", "request_id"}:
        raise ValueError("webhooks accept decision metadata only")
    if kind == "slack":
        payload = {"text": "Mecha decision: " + json.dumps(event, sort_keys=True)}
    elif kind == "pagerduty":
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": "Mecha security decision",
                "source": "mecha",
                "severity": "warning",
                "custom_details": event,
            },
        }
    else:
        raise ValueError("unsupported webhook")
    async with httpx.AsyncClient(timeout=5, follow_redirects=False, trust_env=False) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
