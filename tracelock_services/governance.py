"""Phase 10 governance and resilience contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

DEFAULT_SECRET_MARKERS = (
    "change-me",
    "local-development",
    "local-operator-token",
)


@dataclass(frozen=True, slots=True)
class GovernanceReport:
    environment: str
    valid: bool
    violations: tuple[str, ...]
    strict: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "valid": self.valid,
            "violations": list(self.violations),
            "strict": self.strict,
        }


@dataclass(slots=True)
class OperationalState:
    """In-process readiness state without storing sensitive request content."""

    evidence_failures: int = 0
    last_evidence_error: str | None = None
    last_success_at: str | None = None

    def evidence_succeeded(self) -> None:
        self.last_success_at = datetime.now(UTC).isoformat()
        self.last_evidence_error = None

    def evidence_failed(self, error: Exception) -> None:
        self.evidence_failures += 1
        self.last_evidence_error = type(error).__name__

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_failures": self.evidence_failures,
            "last_evidence_error": self.last_evidence_error,
            "last_success_at": self.last_success_at,
        }


def validate_runtime_config(config: Any) -> GovernanceReport:
    """Validate production-sensitive configuration without exposing secret values."""

    strict = config.environment.lower() in {"production", "prod", "staging"}
    violations: list[str] = []
    secret_fields = (
        "identity_signing_key",
        "provenance_signing_key",
        "policy_signing_key",
        "operator_token",
    )
    if strict:
        for field_name in secret_fields:
            value = getattr(config, field_name, "")
            if not isinstance(value, str) or len(value) < 32:
                violations.append(f"{field_name}_too_short")
                continue
            if any(marker in value.lower() for marker in DEFAULT_SECRET_MARKERS):
                violations.append(f"{field_name}_uses_default_marker")
        if getattr(config, "evidence_db_path", ":memory:") == ":memory:":
            violations.append("durable_evidence_required")
    valid = not violations
    return GovernanceReport(config.environment, valid, tuple(violations), strict)
