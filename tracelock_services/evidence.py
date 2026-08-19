"""Phase 9 durable privacy-safe evidence and operator case storage."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any

from .gateway import GatewayDecision


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    decision_id: str
    request_id: str
    flow_id: str
    workload_id: str
    destination_id: str
    action: str
    reason_code: str
    sent: bool
    receipt_status: str
    receiver_request_count: int
    body_sha256: str | None
    original_body_sha256: str | None
    classification_summary: tuple[str, ...]
    provenance_confidence: str
    policy_id: str | None
    policy_version: int | None
    matched_rule_id: str | None
    redacted_fields: tuple[str, ...]
    transformation_types: tuple[str, ...]
    created_at: str
    case_status: str = "open"
    operator_note: str | None = None
    operator_id: str | None = None
    updated_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "flow_id": self.flow_id,
            "workload_id": self.workload_id,
            "destination_id": self.destination_id,
            "action": self.action,
            "reason_code": self.reason_code,
            "sent": self.sent,
            "receipt_status": self.receipt_status,
            "receiver_request_count": self.receiver_request_count,
            "body_sha256": self.body_sha256,
            "original_body_sha256": self.original_body_sha256,
            "classification_summary": list(self.classification_summary),
            "provenance_confidence": self.provenance_confidence,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "matched_rule_id": self.matched_rule_id,
            "redacted_fields": list(self.redacted_fields),
            "transformation_types": list(self.transformation_types),
            "created_at": self.created_at,
            "case_status": self.case_status,
            "operator_note": self.operator_note,
            "operator_id": self.operator_id,
            "updated_at": self.updated_at,
        }


class EvidenceStore:
    """SQLite evidence store that never accepts or persists raw payloads."""

    def __init__(self, database_path: str = ":memory:") -> None:
        self.database_path = database_path
        self._lock = Lock()
        self._connection = sqlite3.connect(
            database_path,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                decision_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                flow_id TEXT NOT NULL,
                workload_id TEXT NOT NULL,
                destination_id TEXT NOT NULL,
                action TEXT NOT NULL,
                reason_code TEXT NOT NULL,
                sent INTEGER NOT NULL,
                receipt_status TEXT NOT NULL,
                receiver_request_count INTEGER NOT NULL,
                body_sha256 TEXT,
                original_body_sha256 TEXT,
                classification_summary TEXT NOT NULL,
                provenance_confidence TEXT NOT NULL,
                policy_id TEXT,
                policy_version INTEGER,
                matched_rule_id TEXT,
                redacted_fields TEXT NOT NULL,
                transformation_types TEXT NOT NULL,
                created_at TEXT NOT NULL,
                case_status TEXT NOT NULL DEFAULT 'open',
                operator_note TEXT,
                operator_id TEXT,
                updated_at TEXT
            )
            """
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_created_at ON evidence(created_at)"
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(case_status)"
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_workload ON evidence(workload_id)"
        )
        self._connection.commit()

    def health_check(self) -> bool:
        """Verify the evidence database can execute a harmless query."""
        try:
            with self._lock:
                self._connection.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def record(self, decision: GatewayDecision) -> EvidenceRecord:
        record = EvidenceRecord(
            decision_id=decision.decision_id,
            request_id=decision.request_id,
            flow_id=decision.flow_id,
            workload_id=decision.workload_id,
            destination_id=decision.destination_id,
            action=decision.action.value,
            reason_code=decision.reason_code,
            sent=decision.sent,
            receipt_status=decision.receipt_status.value,
            receiver_request_count=decision.receiver_request_count,
            body_sha256=decision.body_sha256,
            original_body_sha256=decision.original_body_sha256,
            classification_summary=decision.classification_summary,
            provenance_confidence=decision.provenance_confidence,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            matched_rule_id=decision.matched_rule_id,
            redacted_fields=decision.redacted_fields,
            transformation_types=decision.transformation_types,
            created_at=datetime.now(UTC).isoformat(),
        )
        with self._lock:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO evidence (
                    decision_id, request_id, flow_id, workload_id, destination_id,
                    action, reason_code, sent, receipt_status, receiver_request_count,
                    body_sha256, original_body_sha256, classification_summary,
                    provenance_confidence, policy_id, policy_version, matched_rule_id,
                    redacted_fields, transformation_types, created_at, case_status,
                    operator_note, operator_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._parameters(record),
            )
            self._connection.commit()
        return record

    def count(self) -> int:
        with self._lock:
            row = self._connection.execute("SELECT COUNT(*) FROM evidence").fetchone()
        return int(row[0]) if row else 0

    def get(self, decision_id: str) -> EvidenceRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM evidence WHERE decision_id = ?", (decision_id,)
            ).fetchone()
        return self._from_row(row) if row else None

    def search(
        self,
        *,
        action: str | None = None,
        case_status: str | None = None,
        workload_id: str | None = None,
        destination_id: str | None = None,
        limit: int = 50,
    ) -> list[EvidenceRecord]:
        clauses: list[str] = []
        values: list[Any] = []
        for column, value in (
            ("action", action),
            ("case_status", case_status),
            ("workload_id", workload_id),
            ("destination_id", destination_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        safe_limit = max(1, min(limit, 200))
        values.append(safe_limit)
        with self._lock:
            rows = self._connection.execute(
                f"SELECT * FROM evidence {where} ORDER BY created_at DESC LIMIT ?",
                values,
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def update_case(
        self,
        decision_id: str,
        *,
        case_status: str,
        operator_id: str,
        operator_note: str | None = None,
    ) -> EvidenceRecord | None:
        if case_status not in {"open", "acknowledged", "investigating", "closed"}:
            raise ValueError("invalid_case_status")
        updated_at = datetime.now(UTC).isoformat()
        with self._lock:
            self._connection.execute(
                """
                UPDATE evidence
                SET case_status = ?, operator_id = ?, operator_note = ?, updated_at = ?
                WHERE decision_id = ?
                """,
                (case_status, operator_id, operator_note, updated_at, decision_id),
            )
            self._connection.commit()
        return self.get(decision_id)

    @staticmethod
    def _parameters(record: EvidenceRecord) -> tuple[Any, ...]:
        return (
            record.decision_id,
            record.request_id,
            record.flow_id,
            record.workload_id,
            record.destination_id,
            record.action,
            record.reason_code,
            int(record.sent),
            record.receipt_status,
            record.receiver_request_count,
            record.body_sha256,
            record.original_body_sha256,
            json.dumps(record.classification_summary),
            record.provenance_confidence,
            record.policy_id,
            record.policy_version,
            record.matched_rule_id,
            json.dumps(record.redacted_fields),
            json.dumps(record.transformation_types),
            record.created_at,
            record.case_status,
            record.operator_note,
            record.operator_id,
            record.updated_at,
        )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> EvidenceRecord:
        return EvidenceRecord(
            decision_id=row["decision_id"],
            request_id=row["request_id"],
            flow_id=row["flow_id"],
            workload_id=row["workload_id"],
            destination_id=row["destination_id"],
            action=row["action"],
            reason_code=row["reason_code"],
            sent=bool(row["sent"]),
            receipt_status=row["receipt_status"],
            receiver_request_count=row["receiver_request_count"],
            body_sha256=row["body_sha256"],
            original_body_sha256=row["original_body_sha256"],
            classification_summary=tuple(json.loads(row["classification_summary"])),
            provenance_confidence=row["provenance_confidence"],
            policy_id=row["policy_id"],
            policy_version=row["policy_version"],
            matched_rule_id=row["matched_rule_id"],
            redacted_fields=tuple(json.loads(row["redacted_fields"])),
            transformation_types=tuple(json.loads(row["transformation_types"])),
            created_at=row["created_at"],
            case_status=row["case_status"],
            operator_note=row["operator_note"],
            operator_id=row["operator_id"],
            updated_at=row["updated_at"],
        )
