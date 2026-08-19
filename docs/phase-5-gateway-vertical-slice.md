# Phase 5 Gateway Vertical Slice

## Objective

Phase 5 connects the Phase 4 identity and destination checks to a real bounded request path. The gateway accepts a structured JSON request, validates it before release, records a decision, and sends only verified requests to a synthetic receiver transport.

```text
workload request
      │
      ├── bounded JSON and method checks
      ├── workload credential verification
      ├── registered destination validation
      ├── decision created before release
      │
      ├── BLOCK or UNSUPPORTED → no receiver call
      └── ALLOW → receiver transport → receipt evidence
```

## Request contract

The gateway endpoint is:

```text
POST /v1/egress/authorize-and-send
```

It requires a bearer credential and a request body containing a request ID, workload ID, destination identity, destination URL, method, bounded JSON body, purpose, and operation.

The initial supported methods are `POST`, `PUT`, and `PATCH`. Bodies must be JSON objects or arrays, must be within the configured size limit, and must not exceed the configured nesting depth.

## Decision behavior

| Condition | Action | Receiver request count |
|---|---|---:|
| Valid identity, registered destination, supported method, bounded JSON | `allow` | 1 |
| Invalid or missing identity | `block` | 0 |
| Unknown or invalid destination | `block` | 0 |
| Unsupported method or body | `unsupported` | 0 |
| Receiver receipt | `received` | Recorded separately from authorization |

The gateway records a SHA-256 body hash for correlation but never returns the raw body, credentials, or payload values in the decision response.

## Receiver evidence

The local `InMemoryReceiverTransport` stands in for a controlled destination. It records only a request count and body hash. A blocked request never invokes the transport, allowing the integration tests to prove `receiver_request_count: 0` for denied flows.

This is local evidence only. It does not claim that no bytes crossed every possible network boundary. Production receiver evidence and durable event storage are deferred to later phases.

## Verification

Run the checks from the repository root:

```bash
ruff check .
mypy tracelock_core tracelock_services tests
pytest
```

The gateway vertical-slice tests cover approved delivery, invalid identity, invalid destination, unsupported methods, HTTP endpoint behavior, receiver counts, and raw-payload absence from decisions.

## Deferred work

Phase 5 does not yet implement trusted provenance, classification-aware policy evaluation, redaction, durable evidence, retries, idempotency, real downstream HTTP transport, response inspection, or production identity-provider integration. Those capabilities are deliberately staged for later phases.
