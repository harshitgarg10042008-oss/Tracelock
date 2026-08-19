# TraceLock

TraceLock is a runtime data-flow authorization gateway for controlled outbound HTTP/JSON data movement. It evaluates workload identity, destination identity, data provenance, classification, purpose, transformation history, and policy before releasing an outbound request.

## Project status

**Current phase: Phase 12 — reproducible release package and final evidence.**

This repository is being developed incrementally. Each phase must have a defined scope, automated checks, and an explicit exit review before the next phase begins.

## MVP security claim

Within the enforced boundary, TraceLock will prove the following narrow claim:

> A registered workload cannot release a bounded JSON payload to an unregistered or unauthorized destination unless the request satisfies the active TraceLock policy. Approved requests are released only after authorization, and blocked requests are not released by the gateway.

The initial demonstration will cover three flows:

1. An approved internal aggregate is allowed and received.
2. A confidential external export is blocked before release.
3. A finance payload is redacted, revalidated, reclassified, and released only after the transformed payload is authorized.

## Initial protected boundary

The first implementation protects only outbound requests that satisfy every condition below:

- The request originates from a registered workload.
- Network routing forces the request through the TraceLock gateway.
- The request uses a supported HTTP method and `application/json` content type.
- The body is valid JSON within configured size and nesting limits.
- The destination resolves to a registered destination identity.
- The request includes trusted or explicitly unknown provenance metadata.
- A valid policy snapshot is available.

Traffic outside this boundary is not treated as protected. It must eventually be classified as `UNSUPPORTED`, `UNMONITORED`, or `BOUNDARY_VIOLATION`.

## Initial data model

The MVP supports bounded JSON objects and arrays. Initial classifications are:

| Classification | Default posture |
|---|---|
| `public` | May be allowed to a registered destination when policy permits. |
| `internal` | Blocked unless explicitly allowed by policy. |
| `confidential` | Blocked by default, especially for external destinations. |
| `restricted` | Blocked by default. |
| `unknown` | Blocked for sensitive or external flows. |

Classification is sticky: renaming a field, wrapping it in an array, batching records, or applying an unsupported transformation does not automatically reduce sensitivity.

## Repository layout

```text
tracelock/
├── .github/workflows/       # Continuous integration
├── docs/                    # Architecture, scope, and decision records
├── evidence/                # Reserved durable evidence storage boundary
├── infra/docker/            # Local container image definition
├── policies/                # Typed example policies and test fixtures
├── scripts/                 # Local development and bypass helpers
├── services/                # Reserved service deployment boundaries
├── tests/                   # Unit and integration tests
├── tracelock_core/          # Framework-independent domain contracts
├── tracelock_services/      # Runnable local FastAPI gateway and provenance checks
├── compose.yaml             # Local multi-service topology
├── pyproject.toml           # Python project metadata and tool configuration
└── README.md                # Project charter and development guide
```

## Development principles

TraceLock follows five non-negotiable principles:

1. **Pre-send enforcement:** sensitive requests are evaluated before release.
2. **Fail closed:** unavailable or unverifiable security dependencies cannot authorize sensitive external movement.
3. **Provenance over application labels:** application-provided labels are advisory until verified by an approved source integration.
4. **Evidence without leakage:** standard logs and decision records never contain raw payloads, credentials, or sensitive values.
5. **Honest boundaries:** the system never claims to protect traffic that bypasses the enforced gateway path.

## Phase 12 implementation

Phase 12 packages the completed implementation into a reproducible local demonstration and final acceptance record. The release package includes a clean-checkout file validator, complete verification commands, Docker Desktop bypass instructions, an acceptance matrix, and explicit production limitations.

Run the package checker with:

```bash
python3 scripts/check_release_package.py
```

Operational views remain available through `GET /v1/evidence` and `GET /v1/evidence/{decision_id}`. Controlled case updates use `POST /v1/evidence/{decision_id}/case` and require `X-TraceLock-Operator`. Governance status is available through `GET /v1/governance`, and readiness is exposed through `GET /ready`. The Phase 11 assurance tests and all previous phase behavior remain available.

The available endpoints are:

| Endpoint | Purpose |
|---|---|
| `GET /` | Service metadata, role, environment, version, and current phase. |
| `GET /health` | Basic process health check. |
| `GET /v1/status` | Explicit capability report showing which later-phase features are not implemented yet. |

Run one local role directly:

```bash
TRACELOCK_SERVICE_ROLE=gateway TRACELOCK_SERVICE_NAME=tracelock-gateway \\
  ./scripts/run_local.sh
```

Or start the four-role local topology:

```bash
docker compose -f compose.yaml up --build
```

The gateway is exposed at `http://localhost:8000`. The Phase 3 topology enforces local workload-to-destination separation, Phase 4 verifies workload identity and registered destinations, Phase 5 proves bounded pre-send release control, Phase 6 enforces trusted provenance with sticky classification, Phase 7 evaluates a signed deterministic policy, Phase 8 performs safe redaction followed by transformed-payload re-evaluation, Phase 9 persists privacy-safe evidence with searchable operator workflows, Phase 10 validates governance and readiness before release, Phase 11 exercises the implemented controls through assurance tests, and Phase 12 packages the reproducible demonstration and release evidence. Full penetration testing, capacity benchmarking, distributed recovery, and production security sign-off remain future work.

Verify direct bypass denial after starting Compose:

```bash
docker compose -f compose.yaml exec workload python scripts/check_direct_bypass.py
```

A connection error is the expected result. A successful connection indicates that the local boundary has failed.

## Phase 12 exit criteria

Phase 12 is complete when:

- A fresh clone contains the documented repository structure.
- The Python package can be installed in editable mode.
- Domain contracts exist for classifications, request context, destination identity, and decisions.
- Basic contract tests pass without requiring external services.
- CI runs formatting, linting, type checking, and tests.
- The MVP boundary and non-goals are explicit.
- No secrets or production credentials are committed.
- The local service package exposes health and status endpoints.
- The Compose topology defines separate workload, egress, and control-plane networks.
- The workload is not attached to the egress network.
- The gateway is attached to both workload and egress paths.
- Boundary events never require raw payload values.
- Direct-bypass tests pass.
- Workload credentials reject invalid issuer, audience, expiry, workload, and revoked-token conditions.
- Destinations reject unknown identities, unsafe addresses, invalid paths, and non-TLS URLs.
- Approved bounded requests reach the synthetic receiver.
- Invalid identity and destination requests produce zero receiver calls.
- Unsupported methods and bodies are rejected before release.
- Decisions contain no raw payload values or credentials.
- Provenance requires an approved signed source integration.
- Unknown or renamed field paths are not treated as less sensitive.
- Encoded values retain their trusted classification at the same field path.
- Matching policies produce deterministic actions and reason codes.
- Block rules dominate allows and equal-priority conflicts fail closed.
- Expired or invalidly signed policies cannot authorize release.
- Policy metadata is present in gateway decisions.
- Redaction removes only policy-disallowed field paths.
- Transformed payloads are validated and reclassified before release.
- Transformed payloads are evaluated with transformed-state policy rules.
- Original and final hashes, redacted paths, and transformation types are recorded without payload leakage.
- Gateway decisions are durably recorded in SQLite.
- Evidence search is bounded and filterable.
- Operator case updates require the configured operator credential and use controlled states.
- Production and staging defaults fail governance validation when unsafe.
- Strong production configuration passes governance validation.
- Readiness fails closed when governance or evidence storage is unavailable.
- Operational errors expose only safe type-level information.
- Security outputs do not expose payloads, credentials, signing keys, or operator tokens.
- SQLite evidence survives store reopen and concurrent writes.
- Readiness checks remain within the local performance bound.
- Bypass topology tests pass and the Docker direct-bypass probe is documented.
- The release package checker validates required files.
- A final acceptance matrix maps each implemented control to evidence.
- Reproducible local and Docker Desktop commands are documented.
- Production limitations and deferred assurance work are explicit.
- Service skeleton integration tests pass.

## Explicit non-goals for Phase 12

Phase 12 does not provide an independent penetration test, fuzzing campaign, external load-test report, formal threat-model sign-off, multi-instance recovery test, tamper-evident evidence chain, retention enforcement, asymmetric production key management, or production bypass assessment across all supported network stacks. Those capabilities remain explicit follow-up requirements.

## Local development

The project targets Python 3.11 or newer. After cloning:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dev]'
pytest
```

The commands above are intentionally local and deterministic. External services will be introduced only in the phase that requires them.
