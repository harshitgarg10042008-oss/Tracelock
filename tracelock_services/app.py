"""Local TraceLock service skeleton with Phase 3 boundary observability."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any

import uvicorn
from fastapi import FastAPI

from .boundary import BoundaryEventStore


@dataclass(frozen=True)
class ServiceConfig:
    """Runtime configuration shared by each local service role."""

    service_name: str = "tracelock-gateway"
    service_role: str = "gateway"
    environment: str = "local"
    version: str = "0.1.0"

    @classmethod
    def from_environment(cls) -> ServiceConfig:
        return cls(
            service_name=os.getenv("TRACELOCK_SERVICE_NAME", cls.service_name),
            service_role=os.getenv("TRACELOCK_SERVICE_ROLE", cls.service_role),
            environment=os.getenv("TRACELOCK_ENVIRONMENT", cls.environment),
            version=os.getenv("TRACELOCK_VERSION", cls.version),
        )


def create_app(config: ServiceConfig | None = None) -> FastAPI:
    """Create an isolated application instance for tests or local deployment."""

    runtime = config or ServiceConfig.from_environment()
    events = BoundaryEventStore()
    app = FastAPI(
        title="TraceLock",
        version=runtime.version,
        description="Runtime data-flow authorization service skeleton.",
    )
    app.state.config = runtime
    app.state.boundary_events = events

    @app.get("/", tags=["service"])
    def service_metadata() -> dict[str, Any]:
        return {
            "service": runtime.service_name,
            "role": runtime.service_role,
            "environment": runtime.environment,
            "version": runtime.version,
            "phase": 3,
            "status": "boundary-skeleton",
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
        """Return local boundary events without raw payloads or credentials."""

        return {"events": [event.as_dict() for event in events.list()]}

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
