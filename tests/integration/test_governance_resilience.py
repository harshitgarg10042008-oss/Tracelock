from fastapi.testclient import TestClient

from tracelock_services.app import ServiceConfig, create_app
from tracelock_services.governance import OperationalState, validate_runtime_config


def test_production_defaults_are_rejected_without_exposing_values() -> None:
    report = validate_runtime_config(
        ServiceConfig(environment="production", evidence_db_path=":memory:")
    )

    assert report.valid is False
    assert "durable_evidence_required" in report.violations
    assert all("local-development-signing-key" not in item for item in report.violations)


def test_strong_production_configuration_is_valid() -> None:
    report = validate_runtime_config(
        ServiceConfig(
            environment="production",
            identity_signing_key="i" * 40,
            provenance_signing_key="p" * 40,
            policy_signing_key="k" * 40,
            operator_token="o" * 40,
            evidence_db_path="/var/lib/tracelock/evidence.db",
        )
    )

    assert report.valid is True
    assert report.violations == ()


def test_readiness_and_governance_endpoint_are_safe() -> None:
    client = TestClient(
        create_app(
            ServiceConfig(
                service_name="test-gateway",
                service_role="gateway",
                environment="test",
            )
        )
    )

    ready = client.get("/ready")
    governance = client.get("/v1/governance")

    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert governance.status_code == 200
    body = governance.json()
    assert body["governance"]["valid"] is True
    assert body["evidence"]["ready"] is True
    assert "signing_key" not in str(body)


def test_operational_state_tracks_failures_without_exception_details() -> None:
    state = OperationalState()
    state.evidence_failed(RuntimeError("sensitive database detail"))

    assert state.evidence_failures == 1
    assert state.last_evidence_error == "RuntimeError"
    assert "sensitive database detail" not in str(state.as_dict())
