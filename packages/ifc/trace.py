"""Replayable decision metadata. Value contents and credentials have no schema field."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from packages.core import Confidentiality, Trust, Value
from packages.policy import Decision


class LabelSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    trust: Trust
    confidentiality: Confidentiality
    source_count: int = Field(ge=1)
    sink_count: int = Field(ge=0)

    @classmethod
    def of(cls, value: Value) -> "LabelSnapshot":
        return cls(
            trust=value.label.trust,
            confidentiality=value.label.confidentiality,
            source_count=len(value.label.sources),
            sink_count=len(value.label.allowed_sinks),
        )


class TraceStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    index: int = Field(ge=0, le=31)
    op: Literal["extract", "concat", "call"]
    tool: Literal["send_email", "fetch_url", "summarize", "other"] | None = None
    inputs: tuple[LabelSnapshot, ...]
    output: LabelSnapshot | None = None
    decision: Decision | None = None


class ExecutionTrace(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    policy_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    steps: tuple[TraceStep, ...] = Field(max_length=32)
    effect_count: int = Field(ge=0, le=32)
    halted_at: int | None = Field(default=None, ge=0, le=31)
    skipped_instructions: int = Field(default=0, ge=0, le=31)
