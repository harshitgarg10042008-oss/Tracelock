# Phase 2 Service Skeleton

## Objective

Phase 2 establishes a runnable local environment for TraceLock without prematurely implementing authorization or network enforcement.

## Service roles

The local Compose topology defines four named roles:

| Role | Local purpose |
|---|---|
| `gateway` | Future pre-send enforcement boundary. |
| `workload` | Future registered workload that produces outbound requests. |
| `control-plane` | Future policy, registry, and operational control service. |
| `fake-destination` | Future controlled receiver used to prove downstream behavior. |

All four roles currently run the same small service application with different environment configuration. This keeps the local topology real while avoiding duplicated service code before the responsibilities are implemented.

## Service contract

Every role exposes:

- `GET /` for non-sensitive service metadata.
- `GET /health` for process health.
- `GET /v1/status` for capability state.

The status endpoint explicitly reports that authorization, network enforcement, persistence, and policy evaluation are not yet available. This prevents the Phase 2 skeleton from being mistaken for a security boundary.

## Local operation

A single role can be launched with `scripts/run_local.sh`. The complete local topology can be launched with `docker compose -f compose.yaml up --build` when Docker is available.

The gateway port is the only host-published port in the local topology. The other roles exist on the shared development network and will receive more restrictive connectivity rules when Phase 3 begins.

## Exit criteria

Phase 2 is complete when the package installs, the service application starts, health and metadata endpoints return stable responses, integration tests cover the service contract, and the Compose file describes the four local roles without production claims.

## Deferred to later phases

Phase 2 does not implement authentication, authorization, proxying, destination lookup, network denial, policy evaluation, data inspection, persistence, redaction, or production secrets. These capabilities are deliberately deferred to Phases 3–10.
