"""Local TraceLock service with the Phase 6 trusted-provenance gateway."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import uvicorn
from fastapi import FastAPI, Header
from pydantic import BaseModel

from tracelock_core.contracts import Classification

from .boundary import BoundaryEventStore
from .destinations import DestinationRegistry, RegisteredDestination
from .gateway import Gateway, GatewayRequest, InMemoryReceiverTransport
from .identity import WorkloadCredentialVerifier
from .policy import (
    PolicyAction,
    PolicyBundle,
    PolicyEngine,
    PolicyRule,
    sign_bundle,
)
from .provenance import TrustedProvenanceVerifier


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
            provenance_audience=os.getenv(
                "TRACELOCK_PROVENANCE_AUDIENCE", cls.provenance_audience
            ),
            provenance_signing_key=os.getenv(
                "TRACELOCK_PROVENANCE_SIGNING_KEY", cls.provenance_signing_key
            ),
            policy_signing_key=os.getenv("TRACELOCK_POLICY_SIGNING_KEY", cls.policy_signing_key),
        )


class IdentityVerifyRequest(BaseModel):
    token: str
    expected_workload_id: str


class ProvenanceVerifyRequest(BaseModel):
    token: str


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


def create_app(config: ServiceConfig | None = None) -> FastAPI:
    runtime = config or ServiceConfig.from_environment()
    events = BoundaryEventStore()
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
    app.state.config = runtime
    app.state.boundary_events = events
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
            "phase": 6,
            "status": "provenance-classification-gateway",
        }

    @app.get("/health", tags=["service"])
    def health() -> dict[str, str]:
        return {"status": "ok", "service": runtime.service_name}

    @app.get("/v1/status", tags=["service"])
    def status() -> dict[str, Any]:
        return {
            "service": asdict(runtime),
            "capabilities": {
                "authorization": True,
                "network_enforcement": runtime.service_role == "gateway",
                "identity_verification": True,
                "destination_registration": True,
            "trusted_provenance": True,
            "sticky_classification": True,
            "deterministic_policy": True,
                "gateway_vertical_slice": True,
                "receiver_evidence": True,
                "persistence": False,
                "policy_evaluation": True,
            },
            "boundary": {
                "mode": "gateway-only-egress-topology",
                "direct_bypass": "denied-by-network-policy",
                "event_count": len(events.list()),
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
