# Phase 9 Durable Evidence and Operator Workflows

## Objective

Phase 9 adds durable, privacy-safe evidence around gateway decisions. The gateway stores decision metadata, hashes, classification summaries, policy references, transformation references, receiver counts, and operator case state without storing raw payloads or credentials.

```text
gateway decision
      │
      ▼
SQLite evidence record
      │
      ├── searchable operational view
      └── authenticated operator case update
```

## Evidence record

Each evidence record is keyed by decision ID and includes request and flow correlation IDs, workload and destination identities, action, reason, enforcement state, receipt state, body hashes, classification summary, provenance confidence, policy ID/version/rule, redacted paths, transformation types, and timestamps.

The store intentionally has no payload column. It also does not accept a payload argument. This keeps the privacy contract structural rather than dependent only on logging conventions.

SQLite is used for the local implementation. The Compose gateway mounts `/var/lib/tracelock` through the named `evidence-data` volume and sets `TRACELOCK_EVIDENCE_DB` to `/var/lib/tracelock/evidence.db`. Tests use in-memory or temporary SQLite databases.

## Operational APIs

| Endpoint | Purpose |
|---|---|
| `GET /v1/evidence` | Search records by action, case status, workload, destination, and bounded limit. |
| `GET /v1/evidence/{decision_id}` | Retrieve one privacy-safe decision record. |
| `POST /v1/evidence/{decision_id}/case` | Acknowledge, investigate, or close a case with an operator note. |
| `GET /v1/status` | Report evidence count alongside service and boundary status. |

Operator case updates require the `X-TraceLock-Operator` header matching the configured local operator token. The local implementation returns a fixed operator identity for the demo; production deployments must integrate real operator authentication and authorization.

## Workflow states

Cases use the controlled states `open`, `acknowledged`, `investigating`, and `closed`. Invalid states and unknown decision IDs are rejected. Search results are bounded to a maximum of 200 records per request.

## Verification

```bash
ruff check .
mypy tracelock_core tracelock_services tests
pytest
```

The test suite verifies SQLite persistence across store reopen, privacy-safe serialization, search filters, unauthorized operator rejection, and authorized case updates.

## Deferred work

Phase 9 does not yet implement a full web dashboard, role-based access control, tamper-evident evidence chaining, external database deployment, retention policies, export workflows, or alert routing. Those capabilities are deferred to later phases.
