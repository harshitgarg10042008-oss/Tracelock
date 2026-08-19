from pathlib import Path

from fastapi.testclient import TestClient

from tracelock_services.app import ServiceConfig, create_app
from tracelock_services.boundary import BoundaryEventStore

REPOSITORY_ROOT = Path(__file__).parents[2]


def test_gateway_reports_enforced_boundary_mode() -> None:
    client = TestClient(
        create_app(
            ServiceConfig(
                service_name="test-gateway",
                service_role="gateway",
                environment="test",
            )
        )
    )

    body = client.get("/v1/status").json()
    assert body["capabilities"]["network_enforcement"] is True
    assert body["boundary"]["mode"] == "gateway-only-egress-topology"
    assert body["boundary"]["direct_bypass"] == "denied-by-network-policy"
    assert body["boundary"]["event_count"] == 0
    assert body["boundary"]["evidence_count"] == 0


def test_boundary_event_store_never_requires_payload_values() -> None:
    store = BoundaryEventStore()
    event = store.record(
        event_id="evt_bypass_1",
        event_type="BOUNDARY_VIOLATION",
        workload_id="analytics-workload",
        attempted_destination="fake-destination:8000",
        network_result="denied",
        detail="direct workload egress denied",
    )

    serialized = event.as_dict()
    assert serialized["event_type"] == "BOUNDARY_VIOLATION"
    assert serialized["network_result"] == "denied"
    assert "payload" not in serialized
    assert "body" not in serialized


def test_compose_assigns_destination_only_to_egress_network() -> None:
    compose = (REPOSITORY_ROOT / "compose.yaml").read_text(encoding="utf-8")

    fake_destination = compose.split("  fake-destination:", maxsplit=1)[1]
    workload = compose.split("  workload:", maxsplit=1)[1].split(
        "  control-plane:", maxsplit=1
    )[0]

    assert "- egress-path" in fake_destination
    assert "- workload-path" not in fake_destination
    assert "- workload-path" in workload
    assert "- egress-path" not in workload
    assert "internal: true" in compose
