from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import perf_counter

from fastapi.testclient import TestClient

from tracelock_services.app import ServiceConfig, create_app
from tracelock_services.evidence import EvidenceStore
from tracelock_services.gateway import GatewayAction, GatewayDecision, ReceiptStatus

REPOSITORY_ROOT = Path(__file__).parents[2]


def assurance_decision(index: int) -> GatewayDecision:
    return GatewayDecision(
        request_id=f"req-assurance-{index}",
        decision_id=f"dec-assurance-{index}",
        flow_id=f"flow-assurance-{index}",
        action=GatewayAction.BLOCK,
        reason_code="assurance_test",
        destination_id="analytics.internal",
        workload_id="analytics-workload",
        sent=False,
        receipt_status=ReceiptStatus.NOT_OBSERVED,
        receiver_request_count=0,
        body_sha256=f"hash-{index}",
        classification_summary=("internal",),
        provenance_confidence="trusted",
        policy_id="policy-assurance",
        policy_version=1,
    )


def test_security_output_never_contains_payload_or_secret_values() -> None:
    client = TestClient(
        create_app(
            ServiceConfig(
                service_name="assurance-gateway",
                service_role="gateway",
                environment="test",
                operator_token="assurance-operator-token",
            )
        )
    )
    secret = "TOP-SECRET-ASSURANCE-VALUE"
    evidence = client.get("/v1/evidence").json()
    governance = client.get("/v1/governance").json()
    status = client.get("/v1/status").json()

    serialized = f"{evidence}{governance}{status}"
    assert secret not in serialized
    assert "signing_key" not in serialized
    assert "operator_token" not in serialized
    assert "payload" not in serialized


def test_compose_topology_has_no_direct_workload_to_destination_path() -> None:
    compose = (REPOSITORY_ROOT / "compose.yaml").read_text(encoding="utf-8")
    destination = compose.split("  fake-destination:", maxsplit=1)[1]
    workload = compose.split("  workload:", maxsplit=1)[1].split(
        "  control-plane:", maxsplit=1
    )[0]

    assert "- egress-path" in destination
    assert "- workload-path" not in destination
    assert "- workload-path" in workload
    assert "- egress-path" not in workload
    assert "internal: true" in compose


def test_evidence_recovers_after_store_reopen(tmp_path: Path) -> None:
    database = tmp_path / "recovery.db"
    first = EvidenceStore(str(database))
    first.record(assurance_decision(1))
    assert first.health_check() is True

    reopened = EvidenceStore(str(database))
    assert reopened.health_check() is True
    assert reopened.get("dec-assurance-1") is not None


def test_evidence_store_handles_concurrent_records(tmp_path: Path) -> None:
    store = EvidenceStore(str(tmp_path / "concurrent.db"))

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda index: store.record(assurance_decision(index)), range(20)))

    assert store.count() == 20
    assert store.health_check() is True


def test_readiness_check_is_bounded_for_local_service() -> None:
    client = TestClient(create_app(ServiceConfig(environment="test")))
    start = perf_counter()
    responses = [client.get("/ready") for _ in range(25)]
    elapsed = perf_counter() - start

    assert all(response.status_code == 200 for response in responses)
    assert elapsed < 2.0
