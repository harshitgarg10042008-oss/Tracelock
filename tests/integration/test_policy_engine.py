from datetime import UTC, datetime, timedelta

from tracelock_core.contracts import Classification
from tracelock_services.policy import (
    PolicyAction,
    PolicyBundle,
    PolicyEngine,
    PolicyInput,
    PolicyRule,
    sign_bundle,
)

KEY = "phase7-policy-test-key-with-at-least-32-bytes!!"


def bundle(rules: tuple[PolicyRule, ...], *, expires_in_minutes: int = 5) -> PolicyBundle:
    unsigned = PolicyBundle(
        policy_id="policy-test",
        version=7,
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=expires_in_minutes),
        rules=rules,
        default_actions={
            Classification.PUBLIC: PolicyAction.ALLOW,
            Classification.INTERNAL: PolicyAction.BLOCK,
            Classification.CONFIDENTIAL: PolicyAction.BLOCK,
            Classification.RESTRICTED: PolicyAction.BLOCK,
            Classification.UNKNOWN: PolicyAction.BLOCK,
        },
        signature="",
    )
    return sign_bundle(unsigned, KEY)


def item(**overrides: object) -> PolicyInput:
    values: dict[str, object] = {
        "workload_id": "analytics-workload",
        "destination_id": "analytics.internal",
        "destination_environment": "internal",
        "purpose": "business-analytics",
        "operation": "aggregate",
        "classifications": (Classification.INTERNAL,),
        "field_paths": ("aggregate.order_count",),
        "provenance_confidence": "trusted",
        "record_count": 5,
    }
    values.update(overrides)
    return PolicyInput(**values)  # type: ignore[arg-type]


def rule(rule_id: str, priority: int, action: PolicyAction, reason: str) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        priority=priority,
        action=action,
        reason_code=reason,
        workload_id="analytics-workload",
    )


def test_block_dominates_allow_when_both_match() -> None:
    engine = PolicyEngine(
        bundle(
            (
                rule("allow", 100, PolicyAction.ALLOW, "allowed"),
                rule("block", 80, PolicyAction.BLOCK, "blocked"),
            )
        ),
        signing_key=KEY,
    )

    decision = engine.evaluate(item())

    assert decision.action is PolicyAction.BLOCK
    assert decision.reason_code == "blocked"
    assert decision.matched_rule_id == "block"


def test_equal_priority_conflicting_actions_block() -> None:
    engine = PolicyEngine(
        bundle(
            (
                rule("allow", 100, PolicyAction.ALLOW, "allowed"),
                rule("block", 100, PolicyAction.BLOCK, "blocked"),
            )
        ),
        signing_key=KEY,
    )

    decision = engine.evaluate(item())

    assert decision.action is PolicyAction.BLOCK
    assert decision.reason_code == "policy_conflict"
    assert decision.conflict is True


def test_default_and_expired_policy_are_fail_closed() -> None:
    default_decision = PolicyEngine(bundle(()), signing_key=KEY).evaluate(item())
    expired_decision = PolicyEngine(
        bundle((), expires_in_minutes=-1), signing_key=KEY
    ).evaluate(item())

    assert default_decision.action is PolicyAction.BLOCK
    assert default_decision.reason_code == "default_block"
    assert expired_decision.action is PolicyAction.BLOCK
    assert expired_decision.reason_code == "policy_expired"


def test_invalid_signature_blocks_and_identical_inputs_are_deterministic() -> None:
    signed = bundle((rule("allow", 100, PolicyAction.ALLOW, "allowed"),))
    invalid = PolicyEngine(signed, signing_key="wrong-key")
    valid = PolicyEngine(signed, signing_key=KEY)

    invalid_decision = invalid.evaluate(item())
    first = valid.evaluate(item())
    second = valid.evaluate(item())

    assert invalid_decision.reason_code == "policy_signature_invalid"
    assert first == second
    assert first.action is PolicyAction.ALLOW
