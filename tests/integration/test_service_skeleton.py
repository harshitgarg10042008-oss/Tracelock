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
    assert metadata.json()["phase"] == 4
    assert metadata.json()["status"] == "identity-destination-skeleton"


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
        "authorization": False,
        "network_enforcement": False,
        "identity_verification": True,
        "destination_registration": True,
        "persistence": False,
        "policy_evaluation": False,
    }
