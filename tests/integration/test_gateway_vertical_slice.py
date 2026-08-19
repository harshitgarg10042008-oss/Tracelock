from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from tracelock_core.contracts import Classification
from tracelock_services.app import ServiceConfig, create_app
from tracelock_services.destinations import DestinationRegistry, RegisteredDestination
from tracelock_services.gateway import Gateway, GatewayRequest, InMemoryReceiverTransport
from tracelock_services.identity import WorkloadCredentialVerifier, issue_demo_token
from tracelock_services.policy import (
    PolicyAction,
    PolicyBundle,
    PolicyEngine,
    PolicyRule,
    sign_bundle,
)
from tracelock_services.provenance import (
    ProvenanceLabel,
    TrustedProvenanceVerifier,
    issue_provenance_token,
)

KEY = "phase5-signing-key-with-at-least-32-bytes!!"
ISSUER = "phase5-issuer"
AUDIENCE = "phase5-gateway"
PROVENANCE_KEY = "phase6-provenance-key-with-at-least-32-bytes!!"
PROVENANCE_ISSUER = "phase6-provenance-issuer"
PROVENANCE_AUDIENCE = "phase5-gateway"


def token() -> str:
    return issue_demo_token(
        signing_key=KEY,
        issuer=ISSUER,
        audience=AUDIENCE,
        workload_id="analytics-workload",
        subject="workload:analytics",
        jti="phase5-jti",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def provenance_token() -> str:
    return issue_provenance_token(
        signing_key=PROVENANCE_KEY,
        issuer=PROVENANCE_ISSUER,
        audience=PROVENANCE_AUDIENCE,
        source_integration="analytics-source",
        labels=(
            ProvenanceLabel(
                field_path="aggregate.order_count",
                classification=Classification.INTERNAL,
                source_resource="analytics.orders",
                confidence="high",
            ),
        ),
        jti="phase6-provenance-jti",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def make_gateway() -> tuple[Gateway, InMemoryReceiverTransport]:
    destinations = DestinationRegistry(
        (
            RegisteredDestination(
                destination_id="analytics.internal",
                environment="internal",
                scheme="https",
                host="analytics.example.com",
                port=443,
                allowed_paths=("/v1/orders/summary",),
            ),
        )
    )
    verifier = WorkloadCredentialVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        signing_key=KEY,
        workload_subjects={"analytics-workload": "workload:analytics"},
    )
    provenance_verifier = TrustedProvenanceVerifier(
        issuer=PROVENANCE_ISSUER,
        audience=PROVENANCE_AUDIENCE,
        signing_key=PROVENANCE_KEY,
        approved_integrations={"analytics-source"},
    )
    unsigned_policy = PolicyBundle(
        policy_id="phase7-test-policy",
        version=1,
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        rules=(
            PolicyRule(
                rule_id="allow-test-aggregate",
                priority=100,
                action=PolicyAction.ALLOW,
                reason_code="test_policy_allow",
                workload_id="analytics-workload",
                destination_id="analytics.internal",
                destination_environment="internal",
                purpose="business-analytics",
                operation="aggregate",
                classification_any=(Classification.INTERNAL,),
                provenance_confidence="trusted",
            ),
        ),
        default_actions={
            Classification.PUBLIC: PolicyAction.BLOCK,
            Classification.INTERNAL: PolicyAction.BLOCK,
            Classification.CONFIDENTIAL: PolicyAction.BLOCK,
            Classification.RESTRICTED: PolicyAction.BLOCK,
            Classification.UNKNOWN: PolicyAction.BLOCK,
        },
        signature="",
    )
    policy_key = "phase7-policy-test-key-with-at-least-32-bytes!!"
    policy_engine = PolicyEngine(
        sign_bundle(unsigned_policy, policy_key), signing_key=policy_key
    )
    transport = InMemoryReceiverTransport(("analytics.internal",))
    return (
        Gateway(
            verifier=verifier,
            destinations=destinations,
            transport=transport,
            resolver=lambda _host, _port: ["93.184.216.34"],
            provenance_verifier=provenance_verifier,
            policy_engine=policy_engine,
        ),
        transport,
    )


def request(**overrides: object) -> GatewayRequest:
    values: dict[str, object] = {
        "request_id": "req-phase5",
        "workload_id": "analytics-workload",
        "workload_token": token(),
        "provenance_token": provenance_token(),
        "destination_id": "analytics.internal",
        "destination_url": "https://analytics.example.com/v1/orders/summary",
        "method": "POST",
        "body": {"aggregate": {"order_count": 5}},
        "purpose": "business-analytics",
        "operation": "aggregate",
    }
    values.update(overrides)
    return GatewayRequest(**values)  # type: ignore[arg-type]


def test_approved_request_is_sent_and_receiver_receipt_is_recorded() -> None:
    gateway, transport = make_gateway()

    decision = gateway.authorize_and_send(request())

    assert decision.action == "allow"
    assert decision.reason_code == "policy_allowed"
    assert decision.sent is True
    assert decision.receipt_status == "received"
    assert decision.receiver_request_count == 1
    assert transport.count("analytics.internal") == 1
    assert decision.body_sha256 is not None


def test_unsupported_http_method_is_rejected_before_receiver_transport() -> None:
    gateway, transport = make_gateway()

    decision = gateway.authorize_and_send(request(method="DELETE"))

    assert decision.action == "unsupported"
    assert decision.reason_code == "unsupported_http_method"
    assert decision.sent is False
    assert decision.receipt_status == "not_observed"
    assert transport.count("analytics.internal") == 0


def test_invalid_identity_is_blocked_before_receiver_transport() -> None:
    gateway, transport = make_gateway()

    decision = gateway.authorize_and_send(request(workload_token="invalid-token"))

    assert decision.action == "block"
    assert decision.reason_code == "invalid_credential"
    assert decision.sent is False
    assert decision.receipt_status == "not_observed"
    assert decision.receiver_request_count == 0
    assert transport.count("analytics.internal") == 0


def test_invalid_destination_is_blocked_before_receiver_transport() -> None:
    gateway, transport = make_gateway()

    decision = gateway.authorize_and_send(
        request(destination_url="https://analytics.example.com/v1/not-registered")
    )

    assert decision.action == "block"
    assert decision.reason_code == "path_not_registered"
    assert decision.sent is False
    assert decision.receipt_status == "not_observed"
    assert transport.count("analytics.internal") == 0


def test_http_endpoint_returns_safe_decision_and_no_payload() -> None:
    client = TestClient(
        create_app(
            ServiceConfig(
                identity_issuer=ISSUER,
                identity_audience=AUDIENCE,
                identity_signing_key=KEY,
                provenance_issuer=PROVENANCE_ISSUER,
                provenance_audience=PROVENANCE_AUDIENCE,
                provenance_signing_key=PROVENANCE_KEY,
            )
        )
    )

    response = client.post(
        "/v1/egress/authorize-and-send",
        headers={
            "Authorization": f"Bearer {token()}",
            "X-TraceLock-Provenance": provenance_token(),
        },
        json={
            "request_id": "req-http",
            "workload_id": "analytics-workload",
            "destination_id": "analytics.internal",
            "destination_url": "https://analytics.internal/v1/orders/summary",
            "method": "POST",
            "body": {"aggregate": {"order_count": 5}},
            "purpose": "business-analytics",
            "operation": "aggregate",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "allow"
    assert body["sent"] is True
    assert body["receipt_status"] == "received"
    assert "body" not in body
    assert "payload" not in body
