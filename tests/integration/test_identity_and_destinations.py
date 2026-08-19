from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from tracelock_services.app import ServiceConfig, create_app
from tracelock_services.destinations import DestinationRegistry, RegisteredDestination
from tracelock_services.identity import WorkloadCredentialVerifier, issue_demo_token

KEY = "test-signing-key-with-at-least-32-bytes!!"
ISSUER = "test-issuer"
AUDIENCE = "test-gateway"


def make_token(**overrides: object) -> str:
    values: dict[str, object] = {
        "signing_key": KEY,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "workload_id": "analytics-workload",
        "subject": "workload:analytics",
        "jti": "jti-1",
        "expires_at": datetime.now(UTC) + timedelta(minutes=5),
    }
    values.update(overrides)
    return issue_demo_token(**values)  # type: ignore[arg-type]


def make_verifier(revoked_jti: set[str] | None = None) -> WorkloadCredentialVerifier:
    return WorkloadCredentialVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        signing_key=KEY,
        workload_subjects={"analytics-workload": "workload:analytics"},
        revoked_jti=revoked_jti,
    )


def test_valid_workload_credential_is_verified() -> None:
    result = make_verifier().verify(make_token(), expected_workload_id="analytics-workload")
    assert result.verified is True
    assert result.reason_code == "verified"
    assert result.workload_id == "analytics-workload"


def test_identity_rejects_wrong_audience_expiry_workload_and_revocation() -> None:
    wrong_audience = make_verifier().verify(
        make_token(audience="other-service"), expected_workload_id="analytics-workload"
    )
    expired = make_verifier().verify(
        make_token(expires_at=datetime.now(UTC) - timedelta(minutes=1)),
        expected_workload_id="analytics-workload",
    )
    wrong_workload = make_verifier().verify(
        make_token(workload_id="other-workload"), expected_workload_id="analytics-workload"
    )
    revoked = make_verifier({"jti-1"}).verify(
        make_token(), expected_workload_id="analytics-workload"
    )

    assert wrong_audience.reason_code == "wrong_audience"
    assert expired.reason_code == "expired_credential"
    assert wrong_workload.reason_code == "wrong_workload"
    assert revoked.reason_code == "revoked_credential"


def test_destination_registry_requires_registered_https_path_and_public_resolution() -> None:
    registry = DestinationRegistry(
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
    def public_resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def private_resolver(_host: str, _port: int) -> list[str]:
        return ["127.0.0.1"]

    valid = registry.validate(
        destination_id="analytics.internal",
        requested_url="https://analytics.example.com/v1/orders/summary",
        resolver=public_resolver,
    )
    unknown = registry.validate(
        destination_id="missing",
        requested_url="https://analytics.example.com/v1/orders/summary",
        resolver=public_resolver,
    )
    bad_path = registry.validate(
        destination_id="analytics.internal",
        requested_url="https://analytics.example.com/v1/other",
        resolver=public_resolver,
    )
    private = registry.validate(
        destination_id="analytics.internal",
        requested_url="https://analytics.example.com/v1/orders/summary",
        resolver=private_resolver,
    )
    malformed = registry.validate(
        destination_id="analytics.internal",
        requested_url="https://[not-an-ip]/v1/orders/summary",
        resolver=public_resolver,
    )

    assert valid.valid is True
    assert valid.reason_code == "validated"
    assert unknown.reason_code == "unregistered_destination"
    assert bad_path.reason_code == "path_not_registered"
    assert private.reason_code == "private_or_special_address"
    assert malformed.reason_code == "malformed_destination_url"


def test_service_exposes_identity_and_destination_endpoints() -> None:
    client = TestClient(
        create_app(
            ServiceConfig(
                identity_issuer=ISSUER,
                identity_audience=AUDIENCE,
                identity_signing_key=KEY,
            )
        )
    )

    token_response = client.post(
        "/v1/identity/verify",
        json={"token": make_token(), "expected_workload_id": "analytics-workload"},
    )
    destination_response = client.post(
        "/v1/destinations/validate",
        json={
            "destination_id": "analytics.internal",
            "requested_url": "https://analytics.internal/v1/orders/summary",
        },
    )

    assert token_response.status_code == 200
    assert token_response.json()["reason_code"] == "verified"
    assert destination_response.status_code == 200
    assert destination_response.json()["reason_code"] == "validated"
