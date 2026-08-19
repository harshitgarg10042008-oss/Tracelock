# Phase 6 Trusted Provenance and Sticky Classification

## Objective

Phase 6 adds source-aware field classification to the gateway. Labels are accepted only from an approved signed provenance integration. Application-provided labels are not trusted by themselves.

```text
approved source integration
          │ signed manifest
          ▼
TraceLock verifies issuer, audience, expiry, integration, and labels
          │
          ▼
field-path classification → unknown-field detection → gateway decision
```

## Provenance manifest

A provenance manifest contains signed labels with a canonical field path, classification, source resource, confidence, and sticky flag. The local verifier requires an approved source integration and rejects missing, invalid, expired, incorrectly signed, or unapproved manifests.

The local implementation uses HS256 for deterministic development tests. Production deployments must use protected asymmetric keys, rotation, issuer integration, and independent source controls.

## Sticky classification

Classification is attached to the field path and does not automatically decrease when the value is encoded or represented differently. A confidential label for `customer.email` remains confidential even when the value at that path is base64-like text.

Renaming a field without a corresponding trusted provenance label does not downgrade it. The gateway treats unlabelled fields as unknown and blocks the request before receiver transport. Array paths use a canonical wildcard format such as `customers[*].customer_email`.

| Situation | Result |
|---|---|
| Trusted label matches the field path | Field classification is retained. |
| Field is renamed without a new trusted label | `unknown_provenance`; request blocked. |
| Confidential value is encoded at the same labelled path | Confidential classification remains. |
| Provenance integration is not approved | Manifest rejected. |
| Provenance header is missing | Request blocked with `missing_provenance`. |

## Gateway integration

The gateway accepts the signed manifest through the `X-TraceLock-Provenance` header. A request must pass body limits, provenance verification, field classification, workload identity verification, and destination validation before receiver release.

The decision response includes classification summary and provenance confidence, but never includes the provenance token, raw payload, or sensitive field values.

## Verification

```bash
ruff check .
mypy tracelock_core tracelock_services tests
pytest
```

The test suite covers trusted manifests, unapproved integrations, missing provenance, renamed fields, encoded values, unknown field blocking, and full gateway behavior.

## Deferred work

Phase 6 does not yet implement a full lineage engine, transformation propagation across arbitrary computations, semantic detection of encrypted or compressed values, policy precedence, redaction, or durable provenance evidence. Unsupported transformations remain subject to the fail-closed unknown-provenance posture.
