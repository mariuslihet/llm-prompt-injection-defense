"""Conservative server-owned taint fallback for ordinary tool-calling agents."""

from packages.core import Confidentiality, Label, Trust, Value
from packages.policy import Decision, Policy, evaluate


class TaintSession:
    """Once untrusted/private input is observed, future arguments inherit it.

    This intentionally loses precision. Use the interpreter for per-value flow.
    Caller cannot reset taint or provide labels through this interface.
    """

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._label = Label(sources=frozenset({"session"}), trust=Trust.TRUSTED,
                            allowed_sinks=frozenset({"send_email", "fetch_url"}))

    def observe(self, value: Value) -> None:
        self._label = self._label.join(value.label)

    def authorize(self, tool: str, arguments: dict[str, str]) -> Decision:
        values = {k: Value(data=v, label=self._label) for k, v in arguments.items()}
        return evaluate(self.policy, tool, values, read_untrusted=self._label.trust == Trust.UNTRUSTED)

    @property
    def private(self) -> bool:
        return self._label.confidentiality == Confidentiality.PRIVATE
