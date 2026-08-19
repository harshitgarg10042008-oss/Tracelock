"""Phase 3 boundary-event primitives.

The Docker topology performs the actual local egress separation. These small
contracts make boundary violations observable without storing request bodies.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any


@dataclass(frozen=True, slots=True)
class BoundaryEvent:
    """Privacy-preserving record that protected traffic left its expected path."""

    event_id: str
    event_type: str
    workload_id: str
    attempted_destination: str
    network_result: str
    created_at: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class BoundaryEventStore:
    """Small in-memory event store for the local Phase 3 skeleton."""

    def __init__(self) -> None:
        self._events: list[BoundaryEvent] = []
        self._lock = Lock()

    def record(
        self,
        *,
        event_id: str,
        event_type: str,
        workload_id: str,
        attempted_destination: str,
        network_result: str,
        detail: str,
    ) -> BoundaryEvent:
        event = BoundaryEvent(
            event_id=event_id,
            event_type=event_type,
            workload_id=workload_id,
            attempted_destination=attempted_destination,
            network_result=network_result,
            created_at=datetime.now(UTC).isoformat(),
            detail=detail,
        )
        with self._lock:
            self._events.append(event)
        return event

    def list(self) -> list[BoundaryEvent]:
        with self._lock:
            return list(self._events)
