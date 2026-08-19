"""Local TraceLock service with the Phase 6 trusted-provenance gateway."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tracelock_core.contracts import Classification

from .boundary import BoundaryEventStore
from .destinations import DestinationRegistry, RegisteredDestination
from .evidence import EvidenceStore
from .gateway import Gateway, GatewayRequest, InMemoryReceiverTransport
from .governance import OperationalState, validate_runtime_config
from .identity import WorkloadCredentialVerifier, issue_demo_token
from .operations import OperationsStore
from .policy import (
    PolicyAction,
    PolicyBundle,
    PolicyEngine,
    PolicyRule,
    sign_bundle,
)
from .provenance import ProvenanceLabel, TrustedProvenanceVerifier, issue_provenance_token


@dataclass(frozen=True)
class ServiceConfig:
    service_name: str = "tracelock-gateway"
    service_role: str = "gateway"
    environment: str = "local"
    version: str = "0.1.0"
    identity_issuer: str = "tracelock-local-issuer"
    identity_audience: str = "tracelock-gateway"
    identity_signing_key: str = "local-development-signing-key-change-me"
    provenance_issuer: str = "tracelock-local-provenance"
    provenance_audience: str = "tracelock-gateway"
    provenance_signing_key: str = "local-development-provenance-key-change-me"
    policy_signing_key: str = "local-development-policy-key-change-me"
    evidence_db_path: str = ":memory:"
    operator_token: str = "local-operator-token-change-me"

    @classmethod
    def from_environment(cls) -> ServiceConfig:
        return cls(
            service_name=os.getenv("TRACELOCK_SERVICE_NAME", cls.service_name),
            service_role=os.getenv("TRACELOCK_SERVICE_ROLE", cls.service_role),
            environment=os.getenv("TRACELOCK_ENVIRONMENT", cls.environment),
            version=os.getenv("TRACELOCK_VERSION", cls.version),
            identity_issuer=os.getenv("TRACELOCK_IDENTITY_ISSUER", cls.identity_issuer),
            identity_audience=os.getenv("TRACELOCK_IDENTITY_AUDIENCE", cls.identity_audience),
            identity_signing_key=os.getenv(
                "TRACELOCK_IDENTITY_SIGNING_KEY", cls.identity_signing_key
            ),
            provenance_issuer=os.getenv("TRACELOCK_PROVENANCE_ISSUER", cls.provenance_issuer),
            provenance_audience=os.getenv("TRACELOCK_PROVENANCE_AUDIENCE", cls.provenance_audience),
            provenance_signing_key=os.getenv(
                "TRACELOCK_PROVENANCE_SIGNING_KEY", cls.provenance_signing_key
            ),
            policy_signing_key=os.getenv("TRACELOCK_POLICY_SIGNING_KEY", cls.policy_signing_key),
            evidence_db_path=os.getenv("TRACELOCK_EVIDENCE_DB", cls.evidence_db_path),
            operator_token=os.getenv("TRACELOCK_OPERATOR_TOKEN", cls.operator_token),
        )


class IdentityVerifyRequest(BaseModel):
    token: str
    expected_workload_id: str


class ProvenanceVerifyRequest(BaseModel):
    token: str


class EvidenceSearchRequest(BaseModel):
    action: str | None = None
    case_status: str | None = None
    workload_id: str | None = None
    destination_id: str | None = None
    limit: int = 50


class OperatorCaseUpdate(BaseModel):
    case_status: str
    operator_note: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class IncidentUpdate(BaseModel):
    status: str | None = None
    owner: str | None = None
    comment: str | None = None


class ScenarioRequest(BaseModel):
    scenario: str


class DestinationManagementRequest(BaseModel):
    destination_id: str
    enabled: bool = True


class InvestigationRequest(BaseModel):
    name: str
    filters: dict[str, Any] = {}


class AlertRuleRequest(BaseModel):
    name: str
    event_type: str
    threshold: int = 1
    enabled: bool = True


class DestinationValidateRequest(BaseModel):
    destination_id: str
    requested_url: str


class EgressRequest(BaseModel):
    request_id: str
    flow_id: str | None = None
    workload_id: str
    destination_id: str
    destination_url: str
    method: str = "POST"
    body: dict[str, Any] | list[Any]
    purpose: str
    operation: str


def _default_destinations() -> tuple[RegisteredDestination, ...]:
    return (
        RegisteredDestination(
            destination_id="analytics.internal",
            environment="internal",
            scheme="https",
            host="analytics.internal",
            port=443,
            allowed_paths=("/v1/orders/summary",),
        ),
        RegisteredDestination(
            destination_id="finance.internal",
            environment="internal",
            scheme="https",
            host="finance.internal",
            port=443,
            allowed_paths=("/v1/orders/summary",),
        ),
        RegisteredDestination(
            destination_id="external-webhook",
            environment="external",
            scheme="https",
            host="webhook.example.test",
            port=443,
            allowed_paths=("/v1/events",),
        ),
    )


def _default_policy(signing_key: str) -> PolicyBundle:
    unsigned = PolicyBundle(
        policy_id="tracelock-local-policy",
        version=1,
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=1),
        rules=(
            PolicyRule(
                rule_id="allow-internal-aggregate",
                priority=100,
                action=PolicyAction.ALLOW,
                reason_code="approved_internal_aggregate",
                workload_id="analytics-workload",
                destination_id="analytics.internal",
                destination_environment="internal",
                purpose="business-analytics",
                operation="aggregate",
                classification_any=(Classification.INTERNAL,),
                provenance_confidence="trusted",
                minimum_group_size=1,
            ),
            PolicyRule(
                rule_id="redact-finance-email",
                priority=90,
                action=PolicyAction.REDACT,
                reason_code="finance_minimum_fields",
                workload_id="analytics-workload",
                destination_id="finance.internal",
                destination_environment="internal",
                purpose="finance-reporting",
                fields_any=("customer_id", "customer_email", "order_total"),
                allowed_fields=("customer_id", "order_total"),
                require_transformed=False,
            ),
            PolicyRule(
                rule_id="allow-finance-redacted",
                priority=95,
                action=PolicyAction.ALLOW,
                reason_code="finance_payload_revalidated",
                workload_id="analytics-workload",
                destination_id="finance.internal",
                destination_environment="internal",
                purpose="finance-reporting",
                operation="aggregate",
                provenance_confidence="trusted",
                require_transformed=True,
            ),
            PolicyRule(
                rule_id="block-external-confidential",
                priority=80,
                action=PolicyAction.BLOCK,
                reason_code="confidential_data_external_destination",
                destination_environment="external",
                classification_any=(Classification.CONFIDENTIAL, Classification.RESTRICTED),
            ),
        ),
        default_actions={
            Classification.PUBLIC: PolicyAction.ALLOW,
            Classification.INTERNAL: PolicyAction.BLOCK,
            Classification.CONFIDENTIAL: PolicyAction.BLOCK,
            Classification.RESTRICTED: PolicyAction.BLOCK,
            Classification.UNKNOWN: PolicyAction.BLOCK,
        },
        signature="",
    )
    return sign_bundle(unsigned, signing_key)


def _safe_config(config: ServiceConfig) -> dict[str, Any]:
    values = asdict(config)
    for field_name in (
        "identity_signing_key",
        "provenance_signing_key",
        "policy_signing_key",
        "operator_token",
    ):
        values.pop(field_name, None)
    return values


def create_app(config: ServiceConfig | None = None) -> FastAPI:
    runtime = config or ServiceConfig.from_environment()
    governance = validate_runtime_config(runtime)
    operations = OperationalState()
    team_operations = OperationsStore()
    events = BoundaryEventStore()
    evidence = EvidenceStore(runtime.evidence_db_path)
    destinations = DestinationRegistry(_default_destinations())
    verifier = WorkloadCredentialVerifier(
        issuer=runtime.identity_issuer,
        audience=runtime.identity_audience,
        signing_key=runtime.identity_signing_key,
        workload_subjects={"analytics-workload": "workload:analytics"},
    )
    provenance_verifier = TrustedProvenanceVerifier(
        issuer=runtime.provenance_issuer,
        audience=runtime.provenance_audience,
        signing_key=runtime.provenance_signing_key,
        approved_integrations={"analytics-source"},
    )
    policy_bundle = _default_policy(runtime.policy_signing_key)
    policy_engine = PolicyEngine(policy_bundle, signing_key=runtime.policy_signing_key)
    transport = InMemoryReceiverTransport(tuple(item.destination_id for item in destinations.all()))
    gateway = Gateway(
        verifier=verifier,
        destinations=destinations,
        transport=transport,
        resolver=lambda _host, _port: ["93.184.216.34"],
        provenance_verifier=provenance_verifier,
        policy_engine=policy_engine,
    )
    app = FastAPI(
        title="TraceLock",
        version=runtime.version,
        description="Runtime data-flow authorization gateway.",
    )
    configured_origins = os.getenv(
        "TRACELOCK_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    )
    allowed_origins = [origin.strip() for origin in configured_origins.split(",") if origin.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )
    app.state.config = runtime
    app.state.governance = governance
    app.state.operations = operations
    app.state.team_operations = team_operations
    app.state.boundary_events = events
    app.state.evidence_store = evidence
    app.state.destination_registry = destinations
    app.state.identity_verifier = verifier
    app.state.provenance_verifier = provenance_verifier
    app.state.policy_engine = policy_engine
    app.state.gateway = gateway
    app.state.receiver_transport = transport

    @app.get("/", tags=["service"])
    def service_metadata() -> dict[str, Any]:
        return {
            "service": runtime.service_name,
            "role": runtime.service_role,
            "environment": runtime.environment,
            "version": runtime.version,
            "phase": 10,
            "status": "governed-resilient-gateway",
        }

    @app.get("/health", tags=["service"])
    def health() -> dict[str, str]:
        return {"status": "ok", "service": runtime.service_name}

    @app.get("/v1/status", tags=["service"])
    def status() -> dict[str, Any]:
        return {
            "service": _safe_config(runtime),
            "capabilities": {
                "authorization": True,
                "network_enforcement": runtime.service_role == "gateway",
                "identity_verification": True,
                "destination_registration": True,
                "trusted_provenance": True,
                "sticky_classification": True,
                "deterministic_policy": True,
                "redaction": True,
                "transformed_re_evaluation": True,
                "governance_validation": True,
                "resilience_readiness": True,
                "gateway_vertical_slice": True,
                "receiver_evidence": True,
                "persistence": False,
                "policy_evaluation": True,
            },
            "boundary": {
                "mode": "gateway-only-egress-topology",
                "direct_bypass": "denied-by-network-policy",
                "event_count": len(events.list()),
                "evidence_count": evidence.count(),
                "governance_valid": governance.valid,
                "evidence_ready": evidence.health_check(),
            },
        }

    @app.get("/ready", tags=["service"])
    def readiness() -> dict[str, Any]:
        evidence_ready = evidence.health_check()
        ready = governance.valid and evidence_ready
        if not ready:
            raise HTTPException(status_code=503, detail="service_not_ready")
        return {"status": "ready", "governance": governance.as_dict()}

    @app.post("/v1/auth/login", tags=["auth"])
    def login(request: LoginRequest) -> dict[str, Any]:
        token = team_operations.issue_session(
            request.username, request.password, runtime.operator_token
        )
        member = team_operations.members[request.username]
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "username": member.username,
                "role": member.role,
                "display_name": member.display_name,
            },
        }

    @app.post("/v1/auth/logout", tags=["auth"])
    def logout(authorization: str | None = Header(default=None)) -> dict[str, str]:
        member = team_operations.member_from_token(authorization, runtime.operator_token)
        assert authorization is not None
        team_operations.revoke_session(authorization[7:].strip(), runtime.operator_token)
        return {"status": "signed_out", "username": member.username}

    @app.post("/v1/demo/scenarios", tags=["operations"])
    def run_demo_scenario(
        request: ScenarioRequest, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        team_operations.member_from_token(authorization, runtime.operator_token)
        scenario = request.scenario.lower()
        if scenario == "bypass":
            return {
                "scenario": scenario,
                "action": "block",
                "reason_code": "direct_bypass_detected",
                "sent": False,
                "simulated": True,
            }
        if scenario == "allow":
            destination_id, destination_url, purpose, operation = (
                "analytics.internal",
                "https://analytics.internal/v1/orders/summary",
                "business-analytics",
                "aggregate",
            )
            body: dict[str, Any] = {"aggregate_total": 42}
            labels: tuple[ProvenanceLabel, ...] = (
                ProvenanceLabel(
                    "aggregate_total", Classification.INTERNAL, "analytics-source", "trusted"
                ),
            )
        elif scenario == "redact":
            destination_id, destination_url, purpose, operation = (
                "finance.internal",
                "https://finance.internal/v1/orders/summary",
                "finance-reporting",
                "aggregate",
            )
            body = {
                "customer_id": "cust-1",
                "customer_email": "masked@example.test",
                "order_total": 125,
            }
            labels = tuple(
                ProvenanceLabel(field, Classification.INTERNAL, "analytics-source", "trusted")
                for field in body
            )
        elif scenario == "block":
            destination_id, destination_url, purpose, operation = (
                "external-webhook",
                "https://webhook.example.test/v1/events",
                "external-sync",
                "send",
            )
            body = {"customer_email": "person@example.test"}
            labels = (
                ProvenanceLabel(
                    "customer_email", Classification.CONFIDENTIAL, "analytics-source", "trusted"
                ),
            )
        else:
            raise HTTPException(status_code=400, detail="unknown_scenario")
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        workload_token = issue_demo_token(
            signing_key=runtime.identity_signing_key,
            issuer=runtime.identity_issuer,
            audience=runtime.identity_audience,
            workload_id="analytics-workload",
            subject="workload:analytics",
            jti=f"demo-{uuid4().hex}",
            expires_at=expires_at,
        )
        provenance_token = issue_provenance_token(
            signing_key=runtime.provenance_signing_key,
            issuer=runtime.provenance_issuer,
            audience=runtime.provenance_audience,
            source_integration="analytics-source",
            labels=labels,
            jti=f"prov-{uuid4().hex}",
            expires_at=expires_at,
        )
        result = gateway.authorize_and_send(
            GatewayRequest(
                request_id=f"demo-{uuid4().hex}",
                workload_id="analytics-workload",
                workload_token=workload_token,
                provenance_token=provenance_token,
                destination_id=destination_id,
                destination_url=destination_url,
                method="POST",
                body=body,
                purpose=purpose,
                operation=operation,
            )
        )
        evidence.record(result)
        return {"scenario": scenario, "decision": result.as_dict()}

    @app.get("/v1/auth/me", tags=["auth"])
    def current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        member = team_operations.member_from_token(authorization, runtime.operator_token)
        return {
            "username": member.username,
            "role": member.role,
            "display_name": member.display_name,
        }

    @app.get("/v1/governance", tags=["governance"])
    def governance_status() -> dict[str, Any]:
        return {
            "governance": governance.as_dict(),
            "operations": operations.as_dict(),
            "evidence": {
                "ready": evidence.health_check(),
                "record_count": evidence.count(),
            },
        }

    @app.get("/v1/policy", tags=["policy"])
    def policy_status() -> dict[str, Any]:
        return {
            "policy_id": policy_bundle.policy_id,
            "version": policy_bundle.version,
            "status": policy_bundle.status,
            "expires_at": policy_bundle.expires_at.isoformat(),
            "signature_present": bool(policy_bundle.signature),
        }

    @app.get("/v1/evidence", tags=["evidence"])
    def search_evidence(
        action: str | None = None,
        case_status: str | None = None,
        workload_id: str | None = None,
        destination_id: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        records = evidence.search(
            action=action,
            case_status=case_status,
            workload_id=workload_id,
            destination_id=destination_id,
            limit=limit,
        )
        return {"records": [record.as_dict() for record in records]}

    @app.get("/v1/incidents", tags=["operator"])
    def list_incidents(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        team_operations.member_from_token(authorization, runtime.operator_token)
        return {"incidents": [item.as_dict() for item in team_operations.incidents.values()]}

    @app.patch("/v1/incidents/{decision_id}", tags=["operator"])
    def update_incident(
        decision_id: str, update: IncidentUpdate, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        member = team_operations.member_from_token(authorization, runtime.operator_token)
        team_operations.require_role(member, "admin", "operator")
        incident = team_operations.incident_for(decision_id)
        if update.status is not None:
            if update.status not in {"open", "acknowledged", "investigating", "closed"}:
                raise HTTPException(status_code=400, detail="invalid_incident_status")
            incident.status = update.status
        if update.owner is not None:
            incident.owner = update.owner
        if update.comment:
            incident.comments.append(update.comment)
        incident.updated_at = datetime.now(UTC).isoformat()
        return incident.as_dict()

    @app.get("/v1/events/stream", tags=["operations"])
    async def event_stream(authorization: str | None = Header(default=None)) -> StreamingResponse:
        team_operations.member_from_token(authorization, runtime.operator_token)

        async def generate() -> Any:
            last = team_operations.event_sequence
            while True:
                if team_operations.event_sequence != last:
                    last = team_operations.event_sequence
                    yield f"event: decision\\ndata: {json.dumps({'sequence': last})}\\n\\n"
                else:
                    yield f"event: heartbeat\\ndata: {json.dumps({'sequence': last})}\\n\\n"
                await asyncio.sleep(5)

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/v1/investigations", tags=["operator"])
    def list_investigations(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        team_operations.member_from_token(authorization, runtime.operator_token)
        return {"investigations": list(team_operations.saved_investigations.values())}

    @app.post("/v1/investigations", tags=["operator"])
    def save_investigation(
        request: InvestigationRequest, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        member = team_operations.member_from_token(authorization, runtime.operator_token)
        team_operations.require_role(member, "admin", "operator")
        investigation_id = f"inv_{uuid4().hex}"
        item: dict[str, Any] = {
            "investigation_id": investigation_id,
            "name": request.name,
            "filters": request.filters,
            "created_by": member.username,
            "created_at": datetime.now(UTC).isoformat(),
        }
        team_operations.saved_investigations[investigation_id] = item
        return item

    @app.get("/v1/alerts", tags=["operator"])
    def list_alerts(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        team_operations.member_from_token(authorization, runtime.operator_token)
        return {"alerts": list(team_operations.alert_rules.values())}

    @app.post("/v1/alerts", tags=["operator"])
    def create_alert(
        request: AlertRuleRequest, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        member = team_operations.member_from_token(authorization, runtime.operator_token)
        team_operations.require_role(member, "admin", "operator")
        alert_id = f"alert_{uuid4().hex}"
        item: dict[str, Any] = {
            "alert_id": alert_id,
            "name": request.name,
            "event_type": request.event_type,
            "threshold": request.threshold,
            "enabled": request.enabled,
            "created_by": member.username,
        }
        team_operations.alert_rules[alert_id] = item
        return item

    @app.get("/v1/reports/evidence", tags=["reports"])
    def evidence_report(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        member = team_operations.member_from_token(authorization, runtime.operator_token)
        records = evidence.search(limit=500)
        return {
            "report_type": "evidence_integrity",
            "generated_at": datetime.now(UTC).isoformat(),
            "generated_by": member.username,
            "record_count": len(records),
            "records": [record.as_dict() for record in records],
        }

    @app.post("/v1/evidence/{decision_id}/replay", tags=["evidence"])
    def replay_evidence(
        decision_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        team_operations.member_from_token(authorization, runtime.operator_token)
        record = evidence.get(decision_id)
        if record is None:
            raise HTTPException(status_code=404, detail="evidence_not_found")
        return {
            "replayed": True,
            "sent": False,
            "decision": record.as_dict(),
            "note": "Replay is inspection-only and never calls a receiver.",
        }

    @app.get("/v1/evidence/{decision_id}", tags=["evidence"])
    def get_evidence(decision_id: str) -> dict[str, Any]:
        record = evidence.get(decision_id)
        if record is None:
            return {"error": "evidence_not_found"}
        return record.as_dict()

    @app.post("/v1/evidence/{decision_id}/case", tags=["operator"])
    def update_case(
        decision_id: str,
        update: OperatorCaseUpdate,
        x_tracelock_operator: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if x_tracelock_operator != runtime.operator_token:
            return {"error": "operator_unauthorized"}
        try:
            record = evidence.update_case(
                decision_id,
                case_status=update.case_status,
                operator_id="local-operator",
                operator_note=update.operator_note,
            )
        except ValueError as error:
            return {"error": str(error)}
        if record is None:
            return {"error": "evidence_not_found"}
        return record.as_dict()

    @app.get("/v1/boundary-events", tags=["boundary"])
    def boundary_events() -> dict[str, Any]:
        return {"events": [event.as_dict() for event in events.list()]}

    @app.post("/v1/identity/verify", tags=["identity"])
    def verify_identity(request: IdentityVerifyRequest) -> dict[str, Any]:
        return verifier.verify(
            request.token,
            expected_workload_id=request.expected_workload_id,
        ).as_dict()

    @app.post("/v1/provenance/verify", tags=["provenance"])
    def verify_provenance(request: ProvenanceVerifyRequest) -> dict[str, Any]:
        return provenance_verifier.verify(request.token).as_dict()

    @app.get("/v1/destinations", tags=["destinations"])
    def list_destinations() -> dict[str, Any]:
        return {"destinations": [item.as_dict() for item in destinations.all()]}

    @app.patch("/v1/destinations/{destination_id}", tags=["destinations"])
    def manage_destination(
        destination_id: str,
        request: DestinationManagementRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        member = team_operations.member_from_token(authorization, runtime.operator_token)
        team_operations.require_role(member, "admin", "operator")
        item = team_operations.destinations.setdefault(
            destination_id, {"destination_id": destination_id}
        )
        item["enabled"] = request.enabled
        item["updated_by"] = member.username
        return item

    @app.get("/v1/identities", tags=["identity"])
    def list_identities(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        team_operations.member_from_token(authorization, runtime.operator_token)
        return {"identities": list(team_operations.identities.values())}

    @app.post("/v1/destinations/validate", tags=["destinations"])
    def validate_destination(request: DestinationValidateRequest) -> dict[str, Any]:
        return destinations.validate(
            destination_id=request.destination_id,
            requested_url=request.requested_url,
            resolver=lambda _host, _port: ["93.184.216.34"],
        ).as_dict()

    @app.post("/v1/egress/authorize-and-send", tags=["gateway"])
    def authorize_and_send(
        request: EgressRequest,
        authorization: str | None = Header(default=None),
        x_tracelock_provenance: str | None = Header(default=None),
    ) -> dict[str, Any]:
        token = ""
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        if not evidence.health_check():
            raise HTTPException(status_code=503, detail="evidence_store_unavailable")
        if governance.strict and not governance.valid:
            raise HTTPException(status_code=503, detail="governance_configuration_invalid")
        result = gateway.authorize_and_send(
            GatewayRequest(
                request_id=request.request_id,
                workload_id=request.workload_id,
                workload_token=token,
                provenance_token=x_tracelock_provenance or "",
                destination_id=request.destination_id,
                destination_url=request.destination_url,
                method=request.method.upper(),
                body=request.body,
                purpose=request.purpose,
                operation=request.operation,
            )
        )
        team_operations.next_event()
        try:
            evidence.record(result)
        except Exception as error:
            operations.evidence_failed(error)
            raise HTTPException(status_code=503, detail="evidence_persistence_failed") from error
        operations.evidence_succeeded()
        return result.as_dict()

    return app


app = create_app()


def run() -> None:
    uvicorn.run(
        "tracelock_services.app:app",
        host=os.getenv("TRACELOCK_HOST", "127.0.0.1"),
        port=int(os.getenv("TRACELOCK_PORT", "8000")),
        reload=False,
    )


if __name__ == "__main__":
    run()
