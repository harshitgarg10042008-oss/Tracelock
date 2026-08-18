from tracelock_core import (
    Classification,
    Decision,
    DecisionAction,
    EnforcementStatus,
    ReceiptStatus,
)


def test_classifications_are_explicit_and_stable() -> None:
    assert [item.value for item in Classification] == [
        "public",
        "internal",
        "confidential",
        "restricted",
        "unknown",
    ]


def test_decision_serialization_contains_metadata_but_not_payload() -> None:
    decision = Decision(
        request_id="req_demo",
        decision_id="dec_demo",
        action=DecisionAction.BLOCK,
        reason_code="confidential_data_external_destination",
        policy_id="demo-policy",
        policy_version=1,
        enforcement_status=EnforcementStatus.NOT_SENT,
        receipt_status=ReceiptStatus.NOT_OBSERVED,
        classification_summary=(Classification.CONFIDENTIAL,),
        field_paths=("customers[*].customer_email",),
    )

    serialized = decision.as_dict()

    assert serialized["action"] == "block"
    assert serialized["enforcement_status"] == "not_sent"
    assert serialized["receipt_status"] == "not_observed"
    assert serialized["classification_summary"] == ["confidential"]
    assert serialized["field_paths"] == ["customers[*].customer_email"]
    assert "body" not in serialized
    assert "payload" not in serialized
    assert "customer_email" not in serialized
