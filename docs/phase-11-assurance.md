# Phase 11 Security, Performance, Recovery, and Bypass Assurance

## Objective

Phase 11 turns the implemented TraceLock controls into a repeatable assurance suite. The tests exercise security-output boundaries, direct-bypass topology, SQLite recovery, concurrent evidence writes, readiness performance, governance behavior, provenance, policy, redaction, and operator authorization.

## Assurance matrix

| Area | Verification |
|---|---|
| Secret and payload leakage | Public status, governance, and evidence outputs contain neither raw payload values nor signing keys or operator tokens. |
| Network bypass | Compose topology attaches workloads only to `workload-path` and destinations only to `egress-path`; both networks are internal. |
| Evidence recovery | A decision persists after closing and reopening a SQLite store. |
| Evidence concurrency | Multiple worker threads can record distinct decisions without loss or corruption. |
| Readiness performance | Twenty-five local readiness checks complete within a bounded two-second test threshold. |
| Governance | Unsafe production defaults fail validation while strong production configuration passes. |
| Policy and provenance | Existing tests cover signatures, conflicts, expiry, unknown provenance, and sticky classification. |
| Redaction | Existing tests cover omission, final hash changes, transformed reclassification, and post-redaction policy decisions. |
| Operator authorization | Existing tests cover unauthorized and authorized case updates. |

## Security result

During the Phase 11 assurance pass, the service status endpoint was found to serialize the complete runtime configuration, including signing-key and operator-token values. This was corrected by introducing a safe configuration serializer that removes sensitive fields before public status responses. The regression test now prevents the issue from returning.

> Public operational endpoints must expose configuration state, not configuration secrets.

## Performance scope

The current performance check is intentionally a lightweight local regression guard rather than a capacity claim. It measures repeated readiness checks in the test environment. Production throughput, latency percentiles, memory behavior, and load-shedding thresholds require a separately controlled benchmark environment.

## Recovery scope

The current recovery test covers SQLite store reopen and concurrent writes within one process. It does not claim multi-instance failover, filesystem durability under power loss, distributed locking, or database replication.

## Bypass scope

The Compose topology test proves the intended network attachment contract statically. The container-side direct-bypass probe from Phase 3 remains the required Docker Desktop verification for actual runtime network enforcement:

```bash
docker compose -f compose.yaml exec workload python scripts/check_direct_bypass.py
```

A connection failure is expected. A successful direct connection is a security failure.

## Verification command

```bash
ruff check .
mypy tracelock_core tracelock_services tests
pytest -ra
```

The Phase 11 suite is complete when all checks pass and the working tree is clean.

## Deferred work

Phase 11 does not yet provide an independent penetration test, fuzzing campaign, external load-test report, formal threat-model sign-off, multi-instance recovery test, tamper-evident evidence chain, or production bypass assessment across all supported network stacks. Those items belong in final release assurance.
