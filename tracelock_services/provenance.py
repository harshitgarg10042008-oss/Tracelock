"""Phase 6 trusted provenance and sticky classification primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import jwt
from jwt import InvalidTokenError

from tracelock_core.contracts import Classification

_CLASSIFICATION_ORDER = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
    Classification.UNKNOWN: 4,
}


@dataclass(frozen=True, slots=True)
class ProvenanceLabel:
    """A source-issued label for a canonical field path."""

    field_path: str
    classification: Classification
    source_resource: str
    confidence: str
    sticky: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "field_path": self.field_path,
            "classification": self.classification.value,
            "source_resource": self.source_resource,
            "confidence": self.confidence,
            "sticky": self.sticky,
        }


@dataclass(frozen=True, slots=True)
class ProvenanceVerification:
    """Privacy-safe result of verifying a source-issued provenance manifest."""

    verified: bool
    reason_code: str
    source_integration: str | None = None
    labels: tuple[ProvenanceLabel, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "reason_code": self.reason_code,
            "source_integration": self.source_integration,
            "labels": [label.as_dict() for label in self.labels],
        }


@dataclass(frozen=True, slots=True)
class PayloadClassification:
    """Classification result for a bounded JSON payload."""

    fields: tuple[ProvenanceLabel, ...]
    summary: tuple[Classification, ...]
    unknown_field_paths: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "fields": [field.as_dict() for field in self.fields],
            "summary": [item.value for item in self.summary],
            "unknown_field_paths": list(self.unknown_field_paths),
        }


class TrustedProvenanceVerifier:
    """Verify source-issued provenance manifests signed by an approved integration."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        signing_key: str,
        approved_integrations: set[str],
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.signing_key = signing_key
        self.approved_integrations = set(approved_integrations)

    def verify(self, token: str) -> ProvenanceVerification:
        if not token:
            return ProvenanceVerification(False, "missing_provenance")
        try:
            claims = jwt.decode(
                token,
                self.signing_key,
                algorithms=["HS256"],
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "require": [
                        "exp",
                        "iat",
                        "iss",
                        "aud",
                        "sub",
                        "source_integration",
                        "labels",
                    ]
                },
            )
        except InvalidTokenError as error:
            return ProvenanceVerification(False, self._reason_for_error(error))

        integration = claims.get("source_integration")
        raw_labels = claims.get("labels")
        if not isinstance(integration, str) or integration not in self.approved_integrations:
            return ProvenanceVerification(False, "unapproved_source_integration")
        if not isinstance(raw_labels, list):
            return ProvenanceVerification(False, "invalid_provenance_labels")

        labels: list[ProvenanceLabel] = []
        for raw_label in raw_labels:
            parsed = self._parse_label(raw_label)
            if parsed is None:
                return ProvenanceVerification(False, "invalid_provenance_labels")
            labels.append(parsed)
        return ProvenanceVerification(True, "verified", integration, tuple(labels))

    @staticmethod
    def _parse_label(value: Any) -> ProvenanceLabel | None:
        if not isinstance(value, dict):
            return None
        field_path = value.get("field_path")
        source_resource = value.get("source_resource")
        confidence = value.get("confidence")
        classification = value.get("classification")
        sticky = value.get("sticky", True)
        if not isinstance(field_path, str) or not field_path:
            return None
        if not isinstance(source_resource, str) or not source_resource:
            return None
        if not isinstance(confidence, str) or not confidence:
            return None
        if not isinstance(classification, str) or classification not in {
            item.value for item in Classification if item is not Classification.UNKNOWN
        }:
            return None
        if not isinstance(sticky, bool):
            return None
        return ProvenanceLabel(
            field_path,
            Classification(classification),
            source_resource,
            confidence,
            sticky,
        )

    @staticmethod
    def _reason_for_error(error: InvalidTokenError) -> str:
        name = type(error).__name__
        reasons = {
            "ExpiredSignatureError": "expired_provenance",
            "InvalidIssuerError": "wrong_provenance_issuer",
            "InvalidAudienceError": "wrong_provenance_audience",
            "MissingRequiredClaimError": "missing_provenance_claim",
            "InvalidAlgorithmError": "unsupported_provenance_algorithm",
        }
        return reasons.get(name, "invalid_provenance")


def classify_payload(body: Any, labels: tuple[ProvenanceLabel, ...]) -> PayloadClassification:
    """Apply trusted labels to every leaf field and keep sensitivity sticky."""

    paths = tuple(_leaf_paths(body))
    by_path = {label.field_path: label for label in labels}
    fields: list[ProvenanceLabel] = []
    unknown: list[str] = []
    for path in paths:
        label = by_path.get(path)
        if label is None:
            unknown.append(path)
        else:
            fields.append(label)

    summary_values = {label.classification for label in fields}
    if unknown:
        summary_values.add(Classification.UNKNOWN)
    summary = tuple(sorted(summary_values, key=lambda item: _CLASSIFICATION_ORDER[item]))
    return PayloadClassification(tuple(fields), summary, tuple(unknown))


def _leaf_paths(value: Any, prefix: str = "") -> list[str]:
    if isinstance(value, dict):
        collected: list[str] = []
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            collected.extend(_leaf_paths(child, child_prefix))
        return collected
    if isinstance(value, list):
        wildcard_prefix = f"{prefix}[*]" if prefix else "[*]"
        collected = []
        for child in value:
            collected.extend(_leaf_paths(child, wildcard_prefix))
        return collected or [wildcard_prefix]
    return [prefix or "$"]


def issue_provenance_token(
    *,
    signing_key: str,
    issuer: str,
    audience: str,
    source_integration: str,
    labels: tuple[ProvenanceLabel, ...],
    jti: str,
    expires_at: datetime,
) -> str:
    """Issue a local signed manifest for tests and demonstrations."""

    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": source_integration,
        "source_integration": source_integration,
        "labels": [label.as_dict() for label in labels],
        "jti": jti,
        "iat": datetime.now(UTC),
        "exp": expires_at,
    }
    encoded = jwt.encode(payload, signing_key, algorithm="HS256")
    return encoded if isinstance(encoded, str) else encoded.decode("utf-8")
