from pathlib import Path

from fastapi.testclient import TestClient

from tracelock_services.app import ServiceConfig, create_app
from tracelock_services.evidence import EvidenceStore
from tracelock_services.gateway import GatewayAction, GatewayDecision, ReceiptStatus


def decision() -> GatewayDecision:
    return GatewayDecision(
        request_id="req-evidence",
        decision_id="dec-evidence",
        flow_id="flow-evidence",
        action=GatewayAction.BLOCK,
        reason_code="policy_conflict",
        destination_id="finance.internal",
        workload_id="analytics-workload",
        sent=False,
        receipt_status=ReceiptStatus.NOT_OBSERVED,
        receiver_request_count=0,
        body_sha256="final-hash",
        classification_summary=("confidential",),
        provenance_confidence="trusted",
        policy_id="policy-test",
        policy_version=2,
        matched_rule_id=None,
        original_body_sha256="original-hash",
        redacted_fields=("customer_email",),
        transformation_types=("filter",),
    )


def test_sqlite_evidence_survives_store_reopen_without_payload_values(
    tmp_path: Path,
) -> None:
    database = tmp_path / "evidence.db"
    first = EvidenceStore(str(database))
    first.record(decision())

    reopened = EvidenceStore(str(database))
    record = reopened.get("dec-evidence")

    assert record is not None
    assert record.reason_code == "policy_conflict"
    assert record.redacted_fields == ("customer_email",)
    serialized = record.as_dict()
    assert "payload" not in serialized
    assert "body" not in serialized
    assert "person@example.test" not in str(serialized)


def test_evidence_search_and_operator_case_workflow() -> None:
    app = create_app(
        ServiceConfig(
            service_name="test-gateway",
            service_role="gateway",
            environment="test",
            operator_token="operator-secret",
        )
    )
    app.state.evidence_store.record(decision())
    client = TestClient(app)

    search = client.get("/v1/evidence", params={"action": "block"})
    assert search.status_code == 200
    assert search.json()["records"][0]["decision_id"] == "dec-evidence"

    unauthorized = client.post(
        "/v1/evidence/dec-evidence/case",
        json={"case_status": "acknowledged", "operator_note": "review"},
    )
    assert unauthorized.json() == {"error": "operator_unauthorized"}

    authorized = client.post(
        "/v1/evidence/dec-evidence/case",
        headers={"X-TraceLock-Operator": "operator-secret"},
        json={"case_status": "investigating", "operator_note": "review"},
    )
    assert authorized.status_code == 200
    assert authorized.json()["case_status"] == "investigating"
    assert authorized.json()["operator_id"] == "local-operator"
