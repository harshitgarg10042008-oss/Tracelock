# Phase 8 Redaction and Re-evaluation

## Objective

Phase 8 implements controlled payload transformation. When policy returns `redact`, TraceLock creates a new bounded JSON payload, removes fields outside the permitted set, validates the transformed body, reclassifies it, and evaluates policy again before receiver release.

```text
original payload
      │
      ├── policy: redact
      ▼
field filter → removed-value verification → body limits
      │
      ▼
reclassify transformed payload → policy re-evaluation
      │
      ├── deny → zero receiver calls
      └── allow → send transformed payload only
```

## Redaction behavior

Redaction is implemented as omission, not replacement with a potentially reversible marker. The transformer rebuilds objects and arrays using canonical field paths and keeps only the fields permitted by the matching policy rule.

The gateway records the original body hash, final body hash, redacted field paths, and transformation type. It does not return either payload. A removed value is checked against the serialized transformed payload so sensitive values cannot survive through an accidental copy or nested representation.

## Reclassification and re-evaluation

The transformed payload receives a fresh field-path classification. Unknown transformed paths fail closed. The policy engine then evaluates the transformed state using `transformed: true`, which prevents the original redaction rule from matching repeatedly and allows a dedicated post-redaction rule to authorize the final payload.

| Stage | Evidence |
|---|---|
| Original request | Original body hash and source-issued classifications. |
| Transformation | Redacted paths and transformation type. |
| Reclassification | Final field paths and classification summary. |
| Re-evaluation | Policy ID, version, matched rule, and final action. |
| Receiver release | Final body hash and receiver receipt count. |

## Security boundaries

Phase 8 does not claim that all arbitrary transformations are safe. The implementation supports deterministic field omission only. Encoding, encryption, compression, aggregation semantics, and arbitrary application transformations require additional provenance and policy controls. If the transformed structure cannot be validated or classified, the gateway blocks before receiver transport.

## Verification

```bash
ruff check .
mypy tracelock_core tracelock_services tests
pytest
```

The integration suite covers finance-style confidential-field removal, final-payload hash changes, redaction evidence, transformed policy matching, missing-label blocking, and zero receiver calls for denied flows.

## Deferred work

Phase 8 does not yet implement format-preserving masking, tokenization, cryptographic deletion proofs, durable transformation lineage, streaming transformations, or policy-managed redaction templates. Those capabilities are deferred to later phases.
