"""Phase 7 deterministic policy contracts and evaluator."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from tracelock_core.contracts import Classification


class PolicyAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    priority: int
    action: PolicyAction
    reason_code: str
    workload_id: str | None = None
    destination_id: str | None = None
    destination_environment: str | None = None
    purpose: str | None = None
    operation: str | None = None
    classification_any: tuple[Classification, ...] = ()
    provenance_confidence: str | None = None
    fields_any: tuple[str, ...] = ()
    minimum_group_size: int | None = None
    allowed_fields: tuple[str, ...] = ()
    require_transformed: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "priority": self.priority,
            "action": self.action.value,
            "reason_code": self.reason_code,
            "workload_id": self.workload_id,
            "destination_id": self.destination_id,
            "destination_environment": self.destination_environment,
            "purpose": self.purpose,
            "operation": self.operation,
            "classification_any": [item.value for item in self.classification_any],
            "provenance_confidence": self.provenance_confidence,
            "fields_any": list(self.fields_any),
            "minimum_group_size": self.minimum_group_size,
            "allowed_fields": list(self.allowed_fields),
            "require_transformed": self.require_transformed,
        }


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    policy_id: str
    version: int
    issued_at: datetime
    expires_at: datetime
    rules: tuple[PolicyRule, ...]
    default_actions: dict[Classification, PolicyAction]
    signature: str
    status: str = "active"

    def canonical_payload(self) -> bytes:
        payload = {
            "policy_id": self.policy_id,
            "version": self.version,
            "issued_at": self.issued_at.astimezone(UTC).isoformat(),
            "expires_at": self.expires_at.astimezone(UTC).isoformat(),
            "rules": [rule.as_dict() for rule in self.rules],
            "default_actions": {
                key.value: value.value for key, value in sorted(
                    self.default_actions.items(), key=lambda item: item[0].value
                )
            },
            "status": self.status,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "rules": [rule.as_dict() for rule in self.rules],
            "default_actions": {
                key.value: value.value for key, value in self.default_actions.items()
            },
            "signature": self.signature,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class PolicyInput:
    workload_id: str
    destination_id: str
    destination_environment: str
    purpose: str
    operation: str
    classifications: tuple[Classification, ...]
    field_paths: tuple[str, ...]
    provenance_confidence: str
    record_count: int = 1
    transformed: bool = False


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: PolicyAction
    reason_code: str
    policy_id: str
    policy_version: int
    matched_rule_id: str | None
    conflict: bool = False
    permitted_fields: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "reason_code": self.reason_code,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "matched_rule_id": self.matched_rule_id,
            "conflict": self.conflict,
            "permitted_fields": list(self.permitted_fields),
        }


class PolicyEngine:
    """Evaluate a verified policy bundle deterministically."""

    def __init__(
        self,
        bundle: PolicyBundle,
        *,
        signing_key: str,
        require_signed: bool = True,
    ) -> None:
        self.bundle = bundle
        self.signing_key = signing_key
        self.require_signed = require_signed

    def evaluate(self, item: PolicyInput, *, now: datetime | None = None) -> PolicyDecision:
        current = now or datetime.now(UTC)
        invalid_reason = self._bundle_invalid_reason(current)
        if invalid_reason is not None:
            return PolicyDecision(
                PolicyAction.BLOCK,
                invalid_reason,
                self.bundle.policy_id,
                self.bundle.version,
                None,
            )

        matches = [rule for rule in self.bundle.rules if self._matches(rule, item)]
        if not matches:
            return self._default_decision(item)

        highest_priority = max(rule.priority for rule in matches)
        highest = [rule for rule in matches if rule.priority == highest_priority]
        actions = {rule.action for rule in highest}
        if len(actions) > 1:
            return PolicyDecision(
                PolicyAction.BLOCK,
                "policy_conflict",
                self.bundle.policy_id,
                self.bundle.version,
                None,
                conflict=True,
            )

        blocks = [rule for rule in matches if rule.action is PolicyAction.BLOCK]
        if blocks:
            winner = max(blocks, key=lambda rule: rule.priority)
            return self._decision_from_rule(winner)
        winner = max(highest, key=lambda rule: rule.rule_id)
        return self._decision_from_rule(winner)

    def _bundle_invalid_reason(self, now: datetime) -> str | None:
        if self.bundle.status != "active":
            return "policy_inactive"
        if self.bundle.expires_at <= now:
            return "policy_expired"
        if self.require_signed and not self._signature_valid():
            return "policy_signature_invalid"
        return None

    def _signature_valid(self) -> bool:
        expected = hmac.new(
            self.signing_key.encode(), self.bundle.canonical_payload(), hashlib.sha256
        ).hexdigest()
        return bool(self.bundle.signature) and hmac.compare_digest(expected, self.bundle.signature)

    @staticmethod
    def _matches(rule: PolicyRule, item: PolicyInput) -> bool:
        for expected, actual in (
            (rule.workload_id, item.workload_id),
            (rule.destination_id, item.destination_id),
            (rule.destination_environment, item.destination_environment),
            (rule.purpose, item.purpose),
            (rule.operation, item.operation),
            (rule.provenance_confidence, item.provenance_confidence),
        ):
            if expected is not None and expected != actual:
                return False
        if rule.classification_any and not set(rule.classification_any).intersection(
            item.classifications
        ):
            return False
        if rule.fields_any and not any(
            PolicyEngine._path_matches(expected, actual)
            for expected in rule.fields_any
            for actual in item.field_paths
        ):
            return False
        if rule.minimum_group_size is not None and item.record_count < rule.minimum_group_size:
            return False
        if rule.require_transformed is not None and rule.require_transformed != item.transformed:
            return False
        return True

    @staticmethod
    def _path_matches(expected: str, actual: str) -> bool:
        return expected == actual or expected.endswith("[*]") and actual.startswith(expected[:-3])

    def _default_decision(self, item: PolicyInput) -> PolicyDecision:
        actions = [
            self.bundle.default_actions.get(item_class, PolicyAction.BLOCK)
            for item_class in item.classifications
        ]
        action = PolicyAction.BLOCK if not actions else max(actions, key=lambda value: value.value)
        return PolicyDecision(
            action,
            f"default_{action.value}",
            self.bundle.policy_id,
            self.bundle.version,
            None,
        )

    def _decision_from_rule(self, rule: PolicyRule) -> PolicyDecision:
        return PolicyDecision(
            rule.action,
            rule.reason_code,
            self.bundle.policy_id,
            self.bundle.version,
            rule.rule_id,
            permitted_fields=rule.allowed_fields,
        )


def sign_bundle(bundle: PolicyBundle, signing_key: str) -> PolicyBundle:
    """Return a copy signed with the configured HMAC key."""

    signature = hmac.new(
        signing_key.encode(), bundle.canonical_payload(), hashlib.sha256
    ).hexdigest()
    return PolicyBundle(
        bundle.policy_id,
        bundle.version,
        bundle.issued_at,
        bundle.expires_at,
        bundle.rules,
        bundle.default_actions,
        signature,
        bundle.status,
    )
