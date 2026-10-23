"""A bounded, linear DSL. No eval/exec, branching, imports, loops or raw tool access."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from packages.core import Confidentiality, Label, Trust, Value
from packages.policy import Approvals, Decision, Policy, binding, evaluate


class Extract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    op: Literal["extract"]
    source: str
    output: str


class Concat(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    op: Literal["concat"]
    left: str
    right: str
    output: str


class Call(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    op: Literal["call"]
    tool: str
    arguments: dict[str, str]
    approval: str = ""


Instruction = Annotated[Extract | Concat | Call, Field(discriminator="op")]


class Program(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    instructions: tuple[Instruction, ...] = Field(max_length=32)


class Extracted(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    summary: str = Field(max_length=4096)


def quarantine(value: Value) -> Value:
    """Deterministic extractor with no tool handle; output inherits every input label."""
    parsed = Extracted(summary=value.data[:4096])
    return value.transform(parsed.summary)


def plan(request: str) -> Program:
    """Mock privileged planner accepts trusted request only, never retrieved content."""
    if request == "email-summary":
        return Program.model_validate(
            {
                "instructions": [
                    {"op": "extract", "source": "document", "output": "summary"},
                    {
                        "op": "call",
                        "tool": "send_email",
                        "arguments": {"recipient": "recipient", "body": "summary"},
                    },
                ]
            }
        )
    return Program.model_validate(
        {
            "instructions": [
                {"op": "extract", "source": "document", "output": "summary"},
                {"op": "call", "tool": "summarize", "arguments": {"text": "summary"}},
            ]
        }
    )


class Interpreter:
    """Request-scoped interpreter and mock tool sink; never makes network calls."""

    def __init__(self, policy: Policy, tenant: str, approvals: Approvals | None = None) -> None:
        self.policy, self.tenant = policy, tenant
        self.approvals = approvals or Approvals()
        self.decisions: list[Decision] = []
        self.effects: list[tuple[str, dict[str, str]]] = []
        self.shadow_decisions: list[Decision] = []

    def run(self, program: Program, inputs: dict[str, Value]) -> dict[str, Value]:
        values = inputs.copy()
        # Conservative control taint includes every supplied untrusted input,
        # including unused inputs, rather than relying on declared reads alone.
        untrusted = any(v.label.trust == Trust.UNTRUSTED for v in values.values())
        for instruction in program.instructions:
            if isinstance(instruction, Extract):
                self._fresh(instruction.output, values)
                values[instruction.output] = quarantine(values[instruction.source])
            elif isinstance(instruction, Concat):
                self._fresh(instruction.output, values)
                values[instruction.output] = values[instruction.left].concat(
                    values[instruction.right]
                )
            else:
                arguments = {k: values[v] for k, v in instruction.arguments.items()}
                approved = self.approvals.consume(
                    instruction.approval,
                    binding(self.tenant, self.policy, instruction.tool, arguments),
                )
                decision = evaluate(
                    self.policy,
                    instruction.tool,
                    arguments,
                    read_untrusted=untrusted,
                    approved=approved,
                )
                self.decisions.append(decision)
                # Shadow never executes denied calls in the sandbox. It records
                # would-deny decisions but cannot weaken structural enforcement.
                if self.policy.mode == "shadow":
                    self.shadow_decisions.append(decision)
                if decision.allowed:
                    self.effects.append(
                        (instruction.tool, {k: v.data for k, v in arguments.items()})
                    )
        return values

    @staticmethod
    def _fresh(name: str, values: dict[str, Value]) -> None:
        if name in values:
            raise ValueError("SSA assignment would overwrite an existing label")


def untrusted_value(text: str, source: str = "retrieved") -> Value:
    return Value(data=text, label=Label(sources=frozenset({source}), trust=Trust.UNTRUSTED))


def trusted_value(
    text: str, *, private: bool = False, sinks: frozenset[str] = frozenset()
) -> Value:
    return Value(
        data=text,
        label=Label(
            sources=frozenset({"user"}),
            trust=Trust.TRUSTED,
            confidentiality=Confidentiality.PRIVATE if private else Confidentiality.PUBLIC,
            allowed_sinks=sinks,
        ),
    )
