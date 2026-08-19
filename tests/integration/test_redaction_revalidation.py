from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from tracelock_core.contracts import Classification
from tracelock_services.app import ServiceConfig, create_app
from tracelock_services.identity import issue_demo_token
from tracelock_services.provenance import ProvenanceLabel, issue_provenance_token

IDENTITY_KEY = "phase8-identity-test-key-with-at-least-32-bytes!!"
PROVENANCE_KEY = "phase8-provenance-test-key-with-at-least-32-bytes!!"


def identity_token() -> str:
    return issue_demo_token(
        signing_key=IDENTITY_KEY,
        issuer="phase8-identity-issuer",
        audience="phase8-gateway",
        workload_id="analytics-workload",
        subject="workload:analytics",
        jti="phase8-identity-jti",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def provenance_token(*, include_email: bool = True) -> str:
    labels = [
        ProvenanceLabel(
            field_path="customer_id",
            classification=Classification.INTERNAL,
            source_resource="crm.customers",
            confidence="high",
        ),
        ProvenanceLabel(
            field_path="order_total",
            classification=Classification.INTERNAL,
            source_resource="orders.totals",
            confidence="high",
        ),
    ]
    if include_email:
        labels.append(
            ProvenanceLabel(
                field_path="customer_email",
                classification=Classification.CONFIDENTIAL,
                source_resource="crm.customers",
                confidence="high",
            )
        )
    return issue_provenance_token(
        signing_key=PROVENANCE_KEY,
        issuer="phase8-provenance-issuer",
        audience="phase8-gateway",
        source_integration="analytics-source",
        labels=tuple(labels),
        jti="phase8-provenance-jti",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def client() -> TestClient:
    return TestClient(
        create_app(
            ServiceConfig(
                identity_issuer="phase8-identity-issuer",
                identity_audience="phase8-gateway",
                identity_signing_key=IDENTITY_KEY,
                provenance_issuer="phase8-provenance-issuer",
                provenance_audience="phase8-gateway",
                provenance_signing_key=PROVENANCE_KEY,
                policy_signing_key="local-development-policy-key-change-me",
            )
        )
    )


def payload() -> dict[str, object]:
    return {
        "customer_id": "cust-42",
        "customer_email": "person@example.test",
        "order_total": 1250,
    }


def test_confidential_field_is_redacted_and_transformed_payload_is_revalidated() -> None:
    response = client().post(
        "/v1/egress/authorize-and-send",
        headers={
            "Authorization": f"Bearer {identity_token()}",
            "X-TraceLock-Provenance": provenance_token(),
        },
        json={
            "request_id": "req-redaction",
            "workload_id": "analytics-workload",
            "destination_id": "finance.internal",
            "destination_url": "https://finance.internal/v1/orders/summary",
            "method": "POST",
            "body": payload(),
            "purpose": "finance-reporting",
            "operation": "aggregate",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["action"] == "allow"
    assert result["sent"] is True
    assert result["receiver_request_count"] == 1
    assert result["matched_rule_id"] == "allow-finance-redacted"
    assert result["redacted_fields"] == ["customer_email"]
    assert result["transformation_types"] == ["filter"]
    assert result["original_body_sha256"] != result["body_sha256"]
    assert "person@example.test" not in result.values()


def test_missing_trusted_label_blocks_before_redaction_release() -> None:
    response = client().post(
        "/v1/egress/authorize-and-send",
        headers={
            "Authorization": f"Bearer {identity_token()}",
            "X-TraceLock-Provenance": provenance_token(include_email=False),
        },
        json={
            "request_id": "req-redaction-unknown",
            "workload_id": "analytics-workload",
            "destination_id": "finance.internal",
            "destination_url": "https://finance.internal/v1/orders/summary",
            "method": "POST",
            "body": payload(),
            "purpose": "finance-reporting",
            "operation": "aggregate",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["action"] == "block"
    assert result["reason_code"] == "unknown_provenance"
    assert result["sent"] is False
    assert result["receiver_request_count"] == 0
