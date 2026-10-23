"""Memory and sub-agent outputs retain untrusted provenance across persistence."""

from packages.core import Label, Trust, Value
from packages.detectors import detect


class Memory:
    def __init__(self) -> None:
        self.items: dict[str, Value] = {}
        self.quarantined: dict[str, Value] = {}

    def ingest(self, key: str, value: Value) -> bool:
        # Even a clean detector result does not promote trust.
        label = Label(
            sources=value.label.sources | frozenset({"memory"}),
            trust=Trust.UNTRUSTED,
            confidentiality=value.label.confidentiality,
            allowed_sinks=frozenset(),
        )
        stored = Value(data=value.data, label=label)
        if detect(value.data).action == "block":
            self.quarantined[key] = stored
            return False
        self.items[key] = stored
        return True


def subagent_output(value: Value, agent_id: str) -> Value:
    return Value(
        data=value.data,
        label=Label(
            sources=value.label.sources | frozenset({f"agent:{agent_id}"}),
            trust=Trust.UNTRUSTED,
            confidentiality=value.label.confidentiality,
            allowed_sinks=frozenset(),
        ),
    )
