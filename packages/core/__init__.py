"""Immutable information-flow values. Labels are assigned by trusted adapters."""

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field


class Trust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Confidentiality(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"


class Label(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    sources: frozenset[str] = Field(min_length=1)
    trust: Trust
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    allowed_sinks: frozenset[str] = frozenset()

    def join(self, other: Self) -> "Label":
        """A join never increases trust, declassifies, or expands sink authority."""
        return Label(
            sources=self.sources | other.sources,
            trust=Trust.UNTRUSTED
            if Trust.UNTRUSTED in (self.trust, other.trust)
            else Trust.TRUSTED,
            confidentiality=Confidentiality.PRIVATE
            if Confidentiality.PRIVATE in (self.confidentiality, other.confidentiality)
            else Confidentiality.PUBLIC,
            allowed_sinks=self.allowed_sinks & other.allowed_sinks,
        )


class Value(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    data: str = Field(max_length=65536)
    label: Label

    def concat(self, other: "Value") -> "Value":
        return Value(data=self.data + other.data, label=self.label.join(other.label))

    def transform(self, data: str) -> "Value":
        """Trusted pure transformation; intentionally offers no relabel operation."""
        return Value(data=data, label=self.label)


class Segment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    kind: str = Field(pattern="^(system|user|tool|retrieved|memory|agent-to-agent)$")
    provenance: str
    value: Value

    def spotlight(self) -> str:
        # Length framing plus label metadata; delimiters are not a security boundary.
        return (
            f"DATA[{self.kind};{self.value.label.trust};{len(self.value.data)}]:{self.value.data}"
        )
