from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt
from fastapi import HTTPException


@dataclass
class TeamMember:
    username: str
    role: str
    display_name: str


@dataclass
class Incident:
    incident_id: str
    decision_id: str
    status: str = "open"
    owner: str | None = None
    comments: list[str] = field(default_factory=list)
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class OperationsStore:
    def __init__(self) -> None:
        self.members = {
            "admin": TeamMember("admin", "admin", "TraceLock Admin"),
            "operator": TeamMember("operator", "operator", "TraceLock Operator"),
            "viewer": TeamMember("viewer", "viewer", "TraceLock Viewer"),
        }
        self.incidents: dict[str, Incident] = {}
        self.saved_investigations: dict[str, dict[str, Any]] = {}
        self.alert_rules: dict[str, dict[str, Any]] = {}
        self.event_sequence = 0
        self.destinations: dict[str, dict[str, Any]] = {}
        self.identities: dict[str, dict[str, Any]] = {
            "analytics-workload": {
                "workload_id": "analytics-workload",
                "status": "active",
                "role": "producer",
                "last_seen": None,
            }
        }

    def issue_session(self, username: str, password: str, secret: str) -> str:
        member = self.members.get(username)
        if member is None or password != f"{username}-tracelock-local":
            raise HTTPException(status_code=401, detail="invalid_credentials")
        now = datetime.now(UTC)
        encoded = jwt.encode(
            {"sub": username, "role": member.role, "iat": now, "exp": now + timedelta(hours=8)},
            secret,
            algorithm="HS256",
        )
        return encoded if isinstance(encoded, str) else encoded.decode("utf-8")

    def member_from_token(self, token: str | None, secret: str) -> TeamMember:
        if not token or not token.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="authentication_required")
        try:
            claims = jwt.decode(token[7:].strip(), secret, algorithms=["HS256"])
        except jwt.InvalidTokenError as error:
            raise HTTPException(status_code=401, detail="invalid_session") from error
        member = self.members.get(str(claims.get("sub")))
        if member is None:
            raise HTTPException(status_code=401, detail="unknown_member")
        return member

    @staticmethod
    def require_role(member: TeamMember, *roles: str) -> None:
        if member.role not in roles:
            raise HTTPException(status_code=403, detail="insufficient_role")

    def incident_for(self, decision_id: str) -> Incident:
        return self.incidents.setdefault(decision_id, Incident(f"inc_{uuid4().hex}", decision_id))

    def next_event(self) -> int:
        self.event_sequence += 1
        return self.event_sequence
