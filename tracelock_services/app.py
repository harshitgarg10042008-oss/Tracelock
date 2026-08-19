"""Local TraceLock service with Phase 4 identity and destination checks."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from .boundary import BoundaryEventStore
from .destinations import DestinationRegistry, RegisteredDestination
from .identity import WorkloadCredentialVerifier


@dataclass(frozen=True)
class ServiceConfig:
    """Runtime configuration shared by each local service role."""

    service_name: str = "tracelock-gateway"
    service_role: str = "gateway"
    environment: str = "local"
    version: str = "0.1.0"
    identity_issuer: str = "tracelock-local-issuer"
    identity_audience: str = "tracelock-gateway"
    identity_signing_key: str = "local-development-signing-key-change-me"

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
        )


class IdentityVerifyRequest(BaseModel):
    token: str
    expected_workload_id: str


class DestinationValidateRequest(BaseModel):
    destination_id: str
    requested_url: str


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


def create_app(config: ServiceConfig | None = None) -> FastAPI:
    """Create an isolated application instance for tests or local deployment."""

    runtime = config or ServiceConfig.from_environment()
    events = BoundaryEventStore()
    destinations = DestinationRegistry(_default_destinations())
    verifier = WorkloadCredentialVerifier(
        issuer=runtime.identity_issuer,
        audience=runtime.identity_audience,
        signing_key=runtime.identity_signing_key,
        workload_subjects={"analytics-workload": "workload:analytics"},
    )
    app = FastAPI(
        title="TraceLock",
        version=runtime.version,
        description="Runtime data-flow authorization service skeleton.",
    )
    app.state.config = runtime
    app.state.boundary_events = events
    app.state.destination_registry = destinations
    app.state.identity_verifier = verifier

    @app.get("/", tags=["service"])
    def service_metadata() -> dict[str, Any]:
        return {
            "service": runtime.service_name,
            "role": runtime.service_role,
            "environment": runtime.environment,
            "version": runtime.version,
            "phase": 4,
            "status": "identity-destination-skeleton",
        }

    @app.get("/health", tags=["service"])
    def health() -> dict[str, str]:
        return {"status": "ok", "service": runtime.service_name}

    @app.get("/v1/status", tags=["service"])
    def status() -> dict[str, Any]:
        return {
            "service": asdict(runtime),
            "capabilities": {
                "authorization": False,
                "network_enforcement": runtime.service_role == "gateway",
                "identity_verification": True,
                "destination_registration": True,
                "persistence": False,
                "policy_evaluation": False,
            },
            "boundary": {
                "mode": "gateway-only-egress-topology",
                "direct_bypass": "denied-by-network-policy",
                "event_count": len(events.list()),
            },
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

    return app


app = create_app()


def run() -> None:
    """Launch the configured local service."""

    uvicorn.run(
        "tracelock_services.app:app",
        host=os.getenv("TRACELOCK_HOST", "127.0.0.1"),
        port=int(os.getenv("TRACELOCK_PORT", "8000")),
        reload=False,
    )


if __name__ == "__main__":
    run()
