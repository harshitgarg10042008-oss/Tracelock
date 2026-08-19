"""Phase 5 bounded gateway with Phase 6 provenance and classification."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol
from uuid import uuid4

from .destinations import DestinationRegistry
from .identity import WorkloadCredentialVerifier
from .policy import PolicyAction, PolicyEngine, PolicyInput
from .provenance import TrustedProvenanceVerifier, classify_payload
from .transformations import ensure_removed_values_absent, redact_to_permitted_fields


class GatewayAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    UNSUPPORTED = "unsupported"


class ReceiptStatus(StrEnum):
    NOT_OBSERVED = "not_observed"
    RECEIVED = "received"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class GatewayRequest:
    request_id: str
    workload_id: str
    workload_token: str
    provenance_token: str
    destination_id: str
    destination_url: str
    method: str
    body: Any
    purpose: str
    operation: str


@dataclass(frozen=True, slots=True)
class ReceiverReceipt:
    request_id: str
    destination_id: str
    status: ReceiptStatus
    receiver_request_count: int
    body_sha256: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "destination_id": self.destination_id,
            "status": self.status.value,
            "receiver_request_count": self.receiver_request_count,
            "body_sha256": self.body_sha256,
        }


@dataclass(frozen=True, slots=True)
class GatewayDecision:
    request_id: str
    decision_id: str
    flow_id: str
    action: GatewayAction
    reason_code: str
    destination_id: str
    workload_id: str
    sent: bool
    receipt_status: ReceiptStatus
    receiver_request_count: int
    body_sha256: str | None
    classification_summary: tuple[str, ...] = ()
    provenance_confidence: str = "unknown"
    policy_id: str | None = None
    policy_version: int | None = None
    matched_rule_id: str | None = None
    original_body_sha256: str | None = None
    redacted_fields: tuple[str, ...] = ()
    transformation_types: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "flow_id": self.flow_id,
            "action": self.action.value,
            "reason_code": self.reason_code,
            "destination_id": self.destination_id,
            "workload_id": self.workload_id,
            "sent": self.sent,
            "enforcement_status": "sent" if self.sent else "not_sent",
            "receipt_status": self.receipt_status.value,
            "receiver_request_count": self.receiver_request_count,
            "body_sha256": self.body_sha256,
            "classification_summary": list(self.classification_summary),
            "provenance_confidence": self.provenance_confidence,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "matched_rule_id": self.matched_rule_id,
            "original_body_sha256": self.original_body_sha256,
            "redacted_fields": list(self.redacted_fields),
            "transformation_types": list(self.transformation_types),
        }


class ReceiverTransport(Protocol):
    def send(
        self,
        *,
        request_id: str,
        destination_id: str,
        destination_url: str,
        method: str,
        body: Any,
        body_sha256: str,
    ) -> ReceiverReceipt: ...


class InMemoryReceiverTransport:
    """Synthetic receiver transport for deterministic local demonstrations."""

    def __init__(self, allowed_destinations: tuple[str, ...]) -> None:
        self._counts = {destination: 0 for destination in allowed_destinations}
        self._last_body_sha256: dict[str, str] = {}

    def send(
        self,
        *,
        request_id: str,
        destination_id: str,
        destination_url: str,
        method: str,
        body: Any,
        body_sha256: str,
    ) -> ReceiverReceipt:
        del destination_url, method, body
        if destination_id not in self._counts:
            return ReceiverReceipt(request_id, destination_id, ReceiptStatus.UNKNOWN, 0)
        self._counts[destination_id] += 1
        self._last_body_sha256[destination_id] = body_sha256
        return ReceiverReceipt(
            request_id,
            destination_id,
            ReceiptStatus.RECEIVED,
            self._counts[destination_id],
            body_sha256,
        )

    def count(self, destination_id: str) -> int:
        return self._counts.get(destination_id, 0)


class Gateway:
    """Evaluate and release one bounded JSON egress request."""

    def __init__(
        self,
        *,
        verifier: WorkloadCredentialVerifier,
        destinations: DestinationRegistry,
        transport: ReceiverTransport,
        resolver: Callable[[str, int], list[str]],
        provenance_verifier: TrustedProvenanceVerifier,
        policy_engine: PolicyEngine,
        max_body_bytes: int = 1_048_576,
        max_depth: int = 20,
    ) -> None:
        self.verifier = verifier
        self.destinations = destinations
        self.transport = transport
        self.resolver = resolver
        self.provenance_verifier = provenance_verifier
        self.policy_engine = policy_engine
        self.max_body_bytes = max_body_bytes
        self.max_depth = max_depth

    def authorize_and_send(self, request: GatewayRequest) -> GatewayDecision:
        decision_id = f"dec_{uuid4().hex}"
        flow_id = f"flow_{uuid4().hex}"
        if request.method.upper() not in {"POST", "PUT", "PATCH"}:
            return self._blocked(
                request,
                decision_id,
                flow_id,
                "unsupported_http_method",
                GatewayAction.UNSUPPORTED,
                None,
            )

        body_sha256 = self._body_sha256(request.body)
        unsupported_reason = self._validate_body(request.body, body_sha256)
        if unsupported_reason is not None:
            return self._blocked(
                request,
                decision_id,
                flow_id,
                unsupported_reason,
                GatewayAction.UNSUPPORTED,
                body_sha256,
            )
        assert body_sha256 is not None

        provenance = self.provenance_verifier.verify(request.provenance_token)
        if not provenance.verified:
            return self._blocked(
                request,
                decision_id,
                flow_id,
                provenance.reason_code,
                GatewayAction.BLOCK,
                body_sha256,
            )
        classification = classify_payload(request.body, provenance.labels)
        if classification.unknown_field_paths:
            return self._blocked(
                request,
                decision_id,
                flow_id,
                "unknown_provenance",
                GatewayAction.BLOCK,
                body_sha256,
                classification.summary,
            )

        identity = self.verifier.verify(
            request.workload_token,
            expected_workload_id=request.workload_id,
        )
        if not identity.verified:
            return self._blocked(
                request,
                decision_id,
                flow_id,
                identity.reason_code,
                GatewayAction.BLOCK,
                body_sha256,
                classification.summary,
            )

        destination = self.destinations.validate(
            destination_id=request.destination_id,
            requested_url=request.destination_url,
            resolver=self.resolver,
        )
        if not destination.valid:
            return self._blocked(
                request,
                decision_id,
                flow_id,
                destination.reason_code,
                GatewayAction.BLOCK,
                body_sha256,
                classification.summary,
            )

        registered = self.destinations.get(request.destination_id)
        if registered is None:
            return self._blocked(
                request,
                decision_id,
                flow_id,
                "unregistered_destination",
                GatewayAction.BLOCK,
                body_sha256,
                classification.summary,
            )
        policy = self.policy_engine.evaluate(
            PolicyInput(
                workload_id=request.workload_id,
                destination_id=request.destination_id,
                destination_environment=registered.environment,
                purpose=request.purpose,
                operation=request.operation,
                classifications=classification.summary,
                field_paths=tuple(label.field_path for label in provenance.labels),
                provenance_confidence="trusted",
                transformed=False,
            )
        )
        body_to_send = request.body
        final_hash = body_sha256
        final_classification = classification
        final_policy = policy
        redacted_fields: tuple[str, ...] = ()
        transformation_types: tuple[str, ...] = ()
        original_hash = body_sha256
        if policy.action is PolicyAction.REDACT:
            transformed = redact_to_permitted_fields(request.body, policy.permitted_fields)
            if not ensure_removed_values_absent(
                request.body,
                transformed.transformed_body,
                transformed.redacted_fields,
            ):
                return self._blocked(
                    request,
                    decision_id,
                    flow_id,
                    "redaction_value_survived",
                    GatewayAction.BLOCK,
                    body_sha256,
                    classification.summary,
                    policy.policy_id,
                    policy.policy_version,
                    policy.matched_rule_id,
                )
            if self._validate_body(transformed.transformed_body, transformed.body_sha256):
                return self._blocked(
                    request,
                    decision_id,
                    flow_id,
                    "transformed_payload_invalid",
                    GatewayAction.BLOCK,
                    body_sha256,
                    classification.summary,
                    policy.policy_id,
                    policy.policy_version,
                    policy.matched_rule_id,
                )
            transformed_classification = classify_payload(
                transformed.transformed_body, provenance.labels
            )
            if transformed_classification.unknown_field_paths:
                return self._blocked(
                    request,
                    decision_id,
                    flow_id,
                    "transformed_unknown_provenance",
                    GatewayAction.BLOCK,
                    body_sha256,
                    transformed_classification.summary,
                    policy.policy_id,
                    policy.policy_version,
                    policy.matched_rule_id,
                )
            re_evaluated = self.policy_engine.evaluate(
                PolicyInput(
                    workload_id=request.workload_id,
                    destination_id=request.destination_id,
                    destination_environment=registered.environment,
                    purpose=request.purpose,
                    operation=request.operation,
                    classifications=transformed_classification.summary,
                    field_paths=tuple(
                        label.field_path for label in transformed_classification.fields
                    ),
                    provenance_confidence="trusted",
                    transformed=True,
                )
            )
            if re_evaluated.action is not PolicyAction.ALLOW:
                return self._blocked(
                    request,
                    decision_id,
                    flow_id,
                    re_evaluated.reason_code,
                    GatewayAction.BLOCK,
                    body_sha256,
                    transformed_classification.summary,
                    re_evaluated.policy_id,
                    re_evaluated.policy_version,
                    re_evaluated.matched_rule_id,
                )
            body_to_send = transformed.transformed_body
            final_hash = transformed.body_sha256
            final_policy = re_evaluated
            final_classification = transformed_classification
            redacted_fields = transformed.redacted_fields
            transformation_types = transformed.transformation_types
        elif policy.action is not PolicyAction.ALLOW:
            return self._blocked(
                request,
                decision_id,
                flow_id,
                policy.reason_code,
                GatewayAction.BLOCK,
                body_sha256,
                classification.summary,
                policy.policy_id,
                policy.policy_version,
                policy.matched_rule_id,
            )

        receipt = self.transport.send(
            request_id=request.request_id,
            destination_id=request.destination_id,
            destination_url=destination.canonical_url or request.destination_url,
            method=request.method,
            body=body_to_send,
            body_sha256=final_hash,
        )
        return GatewayDecision(
            request.request_id,
            decision_id,
            flow_id,
            GatewayAction.ALLOW,
            "policy_allowed",
            request.destination_id,
            request.workload_id,
            receipt.status is ReceiptStatus.RECEIVED,
            receipt.status,
            receipt.receiver_request_count,
            final_hash,
            tuple(item.value for item in final_classification.summary),
            "trusted",
            self.policy_engine.bundle.policy_id,
            self.policy_engine.bundle.version,
            final_policy.matched_rule_id,
            original_hash,
            redacted_fields,
            transformation_types,
        )

    def _blocked(
        self,
        request: GatewayRequest,
        decision_id: str,
        flow_id: str,
        reason_code: str,
        action: GatewayAction,
        body_sha256: str | None,
        classification_summary: tuple[Any, ...] = (),
        policy_id: str | None = None,
        policy_version: int | None = None,
        matched_rule_id: str | None = None,
        original_body_sha256: str | None = None,
        redacted_fields: tuple[str, ...] = (),
        transformation_types: tuple[str, ...] = (),
    ) -> GatewayDecision:
        return GatewayDecision(
            request.request_id,
            decision_id,
            flow_id,
            action,
            reason_code,
            request.destination_id,
            request.workload_id,
            False,
            ReceiptStatus.NOT_OBSERVED,
            0,
            body_sha256,
            tuple(
                item.value if hasattr(item, "value") else str(item)
                for item in classification_summary
            ),
            "trusted" if classification_summary else "unknown",
            policy_id,
            policy_version,
            matched_rule_id,
            original_body_sha256,
            redacted_fields,
            transformation_types,
        )

    def _validate_body(self, body: Any, body_sha256: str | None) -> str | None:
        if body_sha256 is None:
            return "invalid_json_body"
        if not isinstance(body, (dict, list)):
            return "json_object_or_array_required"
        if self._depth(body) > self.max_depth:
            return "json_nesting_limit_exceeded"
        encoded_size = len(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode())
        if encoded_size > self.max_body_bytes:
            return "body_size_limit_exceeded"
        return None

    @staticmethod
    def _body_sha256(body: Any) -> str | None:
        try:
            encoded = json.dumps(
                body,
                separators=(",", ":"),
                ensure_ascii=False,
                sort_keys=True,
            ).encode()
        except (TypeError, ValueError):
            return None
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _depth(value: Any) -> int:
        if isinstance(value, dict):
            return 1 + max((Gateway._depth(item) for item in value.values()), default=0)
        if isinstance(value, list):
            return 1 + max((Gateway._depth(item) for item in value), default=0)
        return 0
