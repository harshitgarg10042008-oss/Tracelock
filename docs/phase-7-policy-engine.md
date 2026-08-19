# Phase 7 Deterministic Policy Engine

## Objective

Phase 7 adds a typed policy evaluator between trusted classification and receiver release. The evaluator uses a verified policy bundle, explicit defaults, deterministic matching, conflict handling, signatures, and expiry checks.

```text
identity + destination + provenance + classification + purpose + operation
                                  │
                                  ▼
                         PolicyEngine.evaluate
                                  │
                         allow / block / redact
                                  │
                                  ▼
                         receiver release or deny
```

## Policy model

A policy bundle contains a policy ID, version, issue time, expiry time, typed rules, classification-specific defaults, status, and an HMAC signature in the local implementation. Production deployment must replace local HMAC configuration with protected signing infrastructure and controlled key rotation.

Rules can match workload, destination, destination environment, purpose, operation, classification, provenance confidence, field paths, and minimum record-group size. Rules are human-readable and do not execute arbitrary code.

## Precedence and failure behavior

The evaluator follows these core semantics:

| Condition | Result |
|---|---|
| Bundle inactive, expired, or signature-invalid | Block with a typed policy error. |
| No matching rule | Use the classification-specific default. |
| Equal-priority rules have different actions | Block with `policy_conflict`. |
| A matching block exists | Block, even if an allow also matches. |
| Matching allow rule | Allow only when all gateway checks already passed. |
| Redaction action | Not released in Phase 7; deferred to Phase 8 transformation handling. |

The engine returns the policy ID, version, matched rule ID, action, reason code, conflict state, and permitted fields. It never receives or returns raw payload values.

## Gateway integration

Every Phase 6 request must now pass policy evaluation after identity, destination, and trusted provenance checks. The default local policy allows the approved internal analytics aggregate and blocks confidential or restricted external movement. Requests blocked by policy have zero receiver calls.

The local service exposes:

```text
GET /v1/policy
```

This returns policy metadata only: ID, version, status, expiry, and whether a signature is present.

## Verification

```bash
ruff check .
mypy tracelock_core tracelock_services tests
pytest
```

The test suite covers block dominance, equal-priority conflicts, default actions, expired bundles, invalid signatures, deterministic repeated evaluation, and gateway release integration.

## Deferred work

Phase 7 does not yet implement policy approval workflows, asymmetric signing, policy distribution and cache rollback, redaction execution, durable policy history, or a complete external policy file parser. Those capabilities are intentionally staged for later phases.
