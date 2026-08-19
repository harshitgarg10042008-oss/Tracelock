# TraceLock Phase 12 Release Evidence

## Release scope

Phase 12 packages the TraceLock implementation through Phase 11 into a reproducible local demonstration and final acceptance record. This release package does not claim that every production assurance activity is complete; it makes the implemented boundary, evidence, tests, and limitations explicit.

> TraceLock protects and provides evidence for the HTTP/JSON traffic that is forced through its configured gateway path. It does not claim to protect traffic that bypasses that path.

## Reproducible local demonstration

From a fresh checkout:

```bash
python3 -m pip install -e '.[dev]'
./scripts/check_release_package.py
ruff check .
mypy tracelock_core tracelock_services tests
pytest -ra
```

For the container demonstration on Docker Desktop:

```bash
docker compose -f compose.yaml up --build
```

Verify the gateway service:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/ready
curl http://localhost:8000/v1/status
curl http://localhost:8000/v1/governance
curl http://localhost:8000/v1/policy
```

Verify direct-bypass denial from the workload container:

```bash
docker compose -f compose.yaml exec workload python scripts/check_direct_bypass.py
```

The expected result is a connection failure reported as `DIRECT_BYPASS_DENIED`. A successful connection is a security failure.

## Acceptance matrix

| Acceptance area | Evidence | Status |
|---|---|---|
| Repository foundation | Phase 1 contracts, CI, and development documentation | Complete |
| Local service topology | Phase 2 Compose services and health endpoints | Complete |
| Enforced network boundary | Phase 3 internal networks and direct-bypass probe | Complete; runtime probe requires Docker Desktop |
| Identity and destinations | Phase 4 signed credential and destination validation tests | Complete |
| Gateway vertical slice | Phase 5 pre-send decisions and receiver evidence | Complete |
| Trusted provenance | Phase 6 signed source labels and unknown-field blocking | Complete |
| Deterministic policy | Phase 7 signed bundles, precedence, conflicts, expiry, defaults | Complete |
| Redaction and re-evaluation | Phase 8 transformed payload validation and policy re-check | Complete |
| Durable evidence | Phase 9 SQLite records, search, and operator case workflow | Complete |
| Governance and resilience | Phase 10 configuration validation and readiness gates | Complete |
| Assurance | Phase 11 security, recovery, concurrency, performance, and bypass tests | Complete within documented scope |
| Reproducible release package | Phase 12 package checker, release documentation, and clean verification commands | Complete |

## Verification snapshot

The final local verification command is:

```bash
ruff check . && mypy tracelock_core tracelock_services tests && pytest -ra
```

The Phase 12 release snapshot records **36 passing tests**, with Ruff and mypy passing. The test environment reports one non-failing FastAPI/Starlette `httpx` deprecation warning.

The package checker validates the required release files and prints a machine-readable JSON result:

```bash
python3 scripts/check_release_package.py
```

The committed verification snapshot is available at [`release/phase-12-verification.json`](../release/phase-12-verification.json). It records the final local quality results and the Docker Desktop runtime-verification limitation.

## Security and operational limitations

The release package does not include an independent penetration test, fuzzing campaign, external load test, asymmetric production key management, a real identity provider, distributed database failover, tamper-evident evidence chaining, retention enforcement, a full dashboard, or a production deployment sign-off. These are explicit follow-up requirements, not hidden capabilities.

The local policy and signing keys remain development defaults outside strict production configuration. Phase 10 governance rejects those defaults in production and staging environments. Operators must provide real secret-manager integration, key rotation, authorization, retention, alerting, and deployment controls before making production security claims.

## Release decision

**Phase 12 release package: accepted for reproducible local demonstration and repository review.** It is not an independent production-security certification.
