from fastapi.testclient import TestClient

from tracelock_services.app import ServiceConfig, create_app


def test_gateway_health_and_metadata() -> None:
    client = TestClient(
        create_app(
            ServiceConfig(
                service_name="test-gateway",
                service_role="gateway",
                environment="test",
            )
        )
    )

    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "test-gateway"}

    metadata = client.get("/")
    assert metadata.status_code == 200
    assert metadata.json()["role"] == "gateway"
    assert metadata.json()["phase"] == 10
    assert metadata.json()["status"] == "governed-resilient-gateway"


def test_status_makes_unimplemented_capabilities_explicit() -> None:
    client = TestClient(
        create_app(
            ServiceConfig(
                service_name="test-control-plane",
                service_role="control-plane",
                environment="test",
            )
        )
    )

    body = client.get("/v1/status").json()
    assert body["service"]["service_role"] == "control-plane"
    assert body["capabilities"] == {
        "authorization": True,
        "network_enforcement": False,
        "identity_verification": True,
        "destination_registration": True,
        "trusted_provenance": True,
        "sticky_classification": True,
        "gateway_vertical_slice": True,
        "receiver_evidence": True,
        "deterministic_policy": True,
        "redaction": True,
        "transformed_re_evaluation": True,
        "governance_validation": True,
        "resilience_readiness": True,
        "persistence": False,
        "policy_evaluation": True,
    }


def test_gateway_allows_control_center_cors_origin() -> None:
    client = TestClient(create_app(ServiceConfig(environment="test")))

    response = client.get(
        "/health",
        headers={"Origin": "http://localhost:3000"},
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
