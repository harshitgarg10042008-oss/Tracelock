"""Stable domain contracts for the TraceLock MVP.

These types intentionally contain no network, database, framework, or credential
implementation. Later phases may build adapters around these contracts without
changing the meaning of a decision.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Classification(StrEnum):
    """Sensitivity levels ordered from least to most restrictive."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class DecisionAction(StrEnum):
    """Actions the authorization layer may return."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    UNSUPPORTED = "unsupported"
    UNMONITORED = "unmonitored"


class EnforcementStatus(StrEnum):
    """Whether the gateway released the request."""

    NOT_SENT = "not_sent"
    SENT = "sent"
    UNKNOWN = "unknown"


class ReceiptStatus(StrEnum):
    """What is known about the configured receiver's response."""

    NOT_OBSERVED = "not_observed"
    RECEIVED = "received"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class WorkloadIdentity:
    """Identity presented by a registered workload.

    Cryptographic verification is deliberately implemented in a later phase. This
    contract records the values a verifier must eventually establish.
    """

    workload_id: str
    subject: str
    issuer: str
    audience: str


@dataclass(frozen=True, slots=True)
class DestinationIdentity:
    """Canonical identity for an approved outbound destination."""

    destination_id: str
    environment: str
    scheme: str
    host: str
    port: int
    allowed_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FieldClassification:
    """Classification and provenance summary for one canonical field path."""

    field_path: str
    classification: Classification
    provenance_confidence: str
    source_resource: str | None = None


@dataclass(frozen=True, slots=True)
class RequestContext:
    """All non-body context required for a future policy decision."""

    request_id: str
    flow_id: str
    purpose: str
    operation: str
    workload: WorkloadIdentity
    destination: DestinationIdentity
    classifications: tuple[FieldClassification, ...] = ()


@dataclass(frozen=True, slots=True)
class Decision:
    """Privacy-preserving result of evaluating one outbound movement."""

    request_id: str
    decision_id: str
    action: DecisionAction
    reason_code: str
    policy_id: str
    policy_version: int
    enforcement_status: EnforcementStatus
    receipt_status: ReceiptStatus
    classification_summary: tuple[Classification, ...] = ()
    field_paths: tuple[str, ...] = ()
    transformation_types: tuple[str, ...] = ()

    def as_dict(self) -> Mapping[str, Any]:
        """Return a JSON-compatible representation without payload values."""

        return {
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "action": self.action.value,
            "reason_code": self.reason_code,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "enforcement_status": self.enforcement_status.value,
            "receipt_status": self.receipt_status.value,
            "classification_summary": [item.value for item in self.classification_summary],
            "field_paths": list(self.field_paths),
            "transformation_types": list(self.transformation_types),
        }
