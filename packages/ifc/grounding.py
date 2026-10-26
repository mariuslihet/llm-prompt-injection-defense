"""Pure typed source resolvers. No model, oracle, policy mutation or tool access."""

import json
from dataclasses import dataclass
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from packages.core import Value
from packages.ifc.business import SCHEMAS, AccessReview, Invoice, Ticket


class GroundingError(ValueError):
    """Covered source checks failed; an enforced answer must be withheld."""


class Source(BaseModel):
    # Adapter extensions, including untrusted_note, do not become authority.
    model_config = ConfigDict(extra="ignore", frozen=True)


class InvoiceRecord(Source):
    invoice_id: str
    vendor_id: str
    amount: str
    currency: str
    due_date: str


class VendorRecord(Source):
    vendor_id: str
    status: Literal["verified", "suspended"]


class TicketRecord(Source):
    ticket_id: str
    issue_code: Literal["reset-link-expiry", "login-failure", "billing-error"]


class IncidentRecord(Source):
    ticket_id: str
    affected_users: int = Field(strict=True, ge=1, le=100000)
    work_blocked: bool = Field(strict=True)


class AccessRecord(Source):
    request_id: str
    resource: Literal["analytics-dashboard", "reporting"]


class ApprovalRecord(Source):
    request_id: str
    manager_approved: Literal["yes", "no"]


class FieldCheck(BaseModel):
    model_config = ConfigDict(frozen=True)
    field: str
    proposed: str
    source_value: str
    matched: bool
    sources: tuple[str, ...]
    rule: str


@dataclass(frozen=True)
class GroundedAnswer:
    value: Value
    checks: tuple[FieldCheck, ...]

    @property
    def corrected_fields(self) -> tuple[str, ...]:
        return tuple(check.field for check in self.checks if not check.matched)


def _record(evidence: dict[str, Value], tool: str) -> object:
    packet = json.loads(evidence[tool].data)
    if not isinstance(packet, dict) or packet.get("status") != "success":
        raise GroundingError("required source did not return a successful record")
    record = packet.get("record")
    if not isinstance(record, dict):
        raise GroundingError("source record is missing or malformed")
    return record


def ground_answer(
    candidate: Value,
    evidence: dict[str, Value],
    kind: str,
    *,
    recover_invalid_proposal: bool = False,
) -> GroundedAnswer:
    """Caller supplies only authenticated, scenario-scoped adapter observations.

    Evidence keys are assigned by the dispatcher, never by retrieved content.
    Labels are joined across the proposal and all source evidence, including
    extensions, so grounding cannot grant authority or declassify data.
    """
    try:
        canonical: BaseModel
        sources: dict[str, tuple[str, ...]]
        rules: dict[str, str]
        if kind == "invoice":
            row = InvoiceRecord.model_validate(_record(evidence, "read_invoice"))
            vendor = VendorRecord.model_validate(_record(evidence, "lookup_vendor"))
            if row.vendor_id != vendor.vendor_id or vendor.status != "verified":
                raise GroundingError("invoice vendor linkage or verification failed")
            canonical = Invoice.model_validate(row.model_dump(exclude={"vendor_id"}))
            canonical = canonical.model_copy(update={"amount": f"{Decimal(canonical.amount):.2f}"})
            sources = {key: ("read_invoice", "lookup_vendor") for key in Invoice.model_fields}
            rules = dict.fromkeys(sources, "invoice field with verified vendor linkage")
        elif kind == "support":
            ticket = TicketRecord.model_validate(_record(evidence, "lookup_ticket"))
            history = IncidentRecord.model_validate(_record(evidence, "read_ticket_history"))
            if ticket.ticket_id != history.ticket_id:
                raise GroundingError("ticket and incident history identifiers disagree")
            canonical = Ticket(
                ticket_id=ticket.ticket_id,
                issue_code=ticket.issue_code,
                team="billing" if ticket.issue_code == "billing-error" else "identity",
                severity="high"
                if history.work_blocked and history.affected_users >= 2
                else "normal",
            )
            sources = {
                "ticket_id": ("lookup_ticket", "read_ticket_history"),
                "issue_code": ("lookup_ticket",),
                "team": ("lookup_ticket",),
                "severity": ("read_ticket_history",),
            }
            rules = {
                "ticket_id": "matching ticket identifiers",
                "issue_code": "record issue code",
                "team": "issue-code routing rule",
                "severity": "multiple blocked users require high severity",
            }
        elif kind == "access":
            access = AccessRecord.model_validate(_record(evidence, "lookup_access_request"))
            approval = ApprovalRecord.model_validate(_record(evidence, "check_manager_approval"))
            if access.request_id != approval.request_id:
                raise GroundingError("request and approval identifiers disagree")
            approved = approval.manager_approved == "yes"
            canonical = AccessReview(
                request_id=access.request_id,
                resource=access.resource,
                decision="approved" if approved else "needs-approval",
                reason="manager-approved" if approved else "manager-approval-missing",
            )
            sources = {
                "request_id": ("lookup_access_request", "check_manager_approval"),
                "resource": ("lookup_access_request",),
                "decision": ("check_manager_approval",),
                "reason": ("check_manager_approval",),
            }
            rules = {
                "request_id": "matching request identifiers",
                "resource": "requested resource",
                "decision": "explicit manager approval",
                "reason": "explicit manager approval",
            }
        else:
            raise GroundingError("no source resolver covers this task")
        try:
            proposed = SCHEMAS[kind].model_validate_json(candidate.data).model_dump(mode="json")
        except ValidationError:
            if not recover_invalid_proposal:
                raise
            proposed = {}
        values = canonical.model_dump(mode="json")
        checks = []
        for key, value in values.items():
            old = str(proposed.get(key, "[unusable model output]"))
            matched = key in proposed and (
                Decimal(old) == Decimal(str(value)) if key == "amount" else old == str(value)
            )
            checks.append(
                FieldCheck(
                    field=key,
                    proposed=old,
                    source_value=str(value),
                    matched=matched,
                    sources=sources[key],
                    rule=rules[key],
                )
            )
        label = candidate.label
        for source in evidence.values():
            label = label.join(source.label)
        return GroundedAnswer(Value(data=canonical.model_dump_json(), label=label), tuple(checks))
    except (KeyError, ValidationError, json.JSONDecodeError, TypeError) as exc:
        raise GroundingError("required typed evidence is missing or invalid") from exc
