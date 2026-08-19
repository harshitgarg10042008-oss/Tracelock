# Phase 3 Enforced Network Boundary

## Objective

Phase 3 changes the local topology from a shared development network into a gateway-only egress path. The workload can communicate with the gateway over `workload-path`, but it is not attached to the destination network. The gateway is the only service attached to both sides of the path.

```text
workload ── workload-path ── gateway ── egress-path ── fake-destination
                              │
                              └── control-path ── control-plane
```

The three Compose networks are marked internal for local development. The topology is an enforcement aid, not a complete production firewall or host-integrity guarantee.

## Boundary behavior

| Attempt | Expected result |
|---|---|
| Workload reaches gateway | Network path exists. |
| Gateway reaches fake destination | Egress path exists. |
| Workload reaches fake destination directly | DNS or connection fails because the workload is not on `egress-path`. |
| Workload bypasses the gateway through another host route | Not covered by this Compose-only phase; production routing controls are still required. |

The repository includes `scripts/check_direct_bypass.py`, which runs inside the workload container and expects a connection to `fake-destination:8000` to fail.

## Boundary event contract

`BoundaryEvent` records only event metadata: event ID, event type, workload ID, attempted destination, network result, timestamp, and a safe detail string. It does not accept or store a request body, payload value, credential, or authorization header.

The local gateway exposes `GET /v1/boundary-events` for inspection. The in-memory store is intentionally temporary and will be replaced by durable evidence storage in a later phase.

## Verification

Run the topology with:

```bash
docker compose -f compose.yaml up --build
```

In another terminal, run the direct-bypass probe:

```bash
docker compose -f compose.yaml exec workload python scripts/check_direct_bypass.py
```

Expected output:

```text
DIRECT_BYPASS_DENIED: gaierror
```

The exact exception type may vary by Docker or operating-system networking behavior. Any connection error is a successful denial; a successful TCP connection is a failed Phase 3 check.

## Limitations

This phase does not yet implement workload credentials, gateway proxying, destination registration, policy evaluation, or durable event persistence. The Compose network separation proves the local topology’s direct-bypass behavior, but production deployments will require platform-level egress controls, DNS and routing controls, host security, and independent bypass testing.
