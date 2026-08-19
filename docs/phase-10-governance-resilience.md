# Phase 10 Governance and Resilience

## Objective

Phase 10 adds production-oriented safeguards around the Phase 9 gateway. Configuration governance prevents unsafe production defaults, readiness checks verify that required evidence storage is available, and operational state reports failures without exposing exception details or secret values.

```text
configuration validation ─┐
                          ├── readiness gate ── gateway request release
 evidence health check ───┘
                                      │
                                      ▼
                         durable evidence persistence
```

## Configuration governance

The service validates production and staging configurations without returning secret values. It rejects default-marker secrets, short signing keys, a memory-only evidence database, and default operator tokens. Development and test environments remain usable with local defaults so the repository can be run without external secret provisioning.

The governance report is exposed at:

```text
GET /v1/governance
```

It includes only the environment, validity, safe violation codes, strictness, evidence readiness, record count, and redacted operational state.

## Resilience and readiness

`GET /health` remains a liveness endpoint. `GET /ready` is the readiness endpoint and returns `503` when governance is invalid or the evidence store cannot execute a health query.

Before an HTTP egress request is evaluated, the gateway checks evidence-store readiness. If evidence persistence is unavailable, the request is rejected before gateway release. After a decision, evidence persistence errors are recorded in operational state and return a generic `503` response without exception details.

The Compose gateway stores SQLite evidence at `/var/lib/tracelock/evidence.db` on the named `evidence-data` volume. This provides local restart persistence while keeping the deployment boundary explicit.

## Operational state

The service tracks only aggregate evidence failures, the exception type name, and the last successful evidence timestamp. It never stores raw payloads, credentials, exception messages, or database paths in operational responses.

## Verification

```bash
ruff check .
mypy tracelock_core tracelock_services tests
pytest
```

The test suite covers production default rejection, strong production configuration acceptance, readiness status, safe governance output, and failure-state privacy.

## Deferred work

Phase 10 does not yet implement multi-instance coordination, distributed locks, database failover, secret-manager integration, asymmetric key rotation, formal change approval, retention enforcement, alert routing, or a complete deployment health policy. Those capabilities are deferred to later assurance and release phases.
