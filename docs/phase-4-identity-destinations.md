# Phase 4 Identity and Destination Registration

## Objective

Phase 4 adds two security gates before future gateway release decisions: verified workload identity and registered destination identity.

## Workload identity

The local verifier accepts signed HS256 JWT credentials only when all required claims are present and valid:

| Claim or check | Required behavior |
|---|---|
| `iss` | Must match the configured issuer. |
| `aud` | Must match the configured TraceLock audience. |
| `sub` | Must match the subject registered for the workload. |
| `workload_id` | Must match the workload requested by the caller. |
| `exp` | Must be present and unexpired. |
| `iat` | Must be present. |
| `jti` | Must be present and not revoked. |
| Algorithm | Only `HS256` is accepted by the local verifier. |

The verifier returns a privacy-safe reason code such as `verified`, `wrong_audience`, `expired_credential`, `wrong_workload`, `unregistered_subject`, or `revoked_credential`. It never returns the token or raw credential contents.

The local signing key is development-only and must be replaced by managed key material and rotation in a production deployment. The Phase 4 verifier establishes the contract; it is not a production identity-provider integration.

## Destination registration

Every outbound URL must match a registered destination identity. Registration controls the scheme, host, port, allowed paths, TLS requirement, and redirect posture. Validation rejects:

- Unknown destination IDs.
- Scheme, host, port, or path mismatches.
- HTTP when TLS is required.
- URL userinfo, query strings, or fragments.
- Empty or failed DNS resolution.
- Loopback, private, link-local, multicast, reserved, or unspecified addresses.

The resolver is injectable for deterministic tests. A production implementation must resolve safely, validate every returned address, control redirects, and revalidate the destination after any network change.

## Service endpoints

| Endpoint | Purpose |
|---|---|
| `POST /v1/identity/verify` | Verify a signed workload credential against an expected workload ID. |
| `GET /v1/destinations` | List registered destination metadata without secrets. |
| `POST /v1/destinations/validate` | Validate a requested URL against a registered destination. |

These endpoints expose security checks for local development and tests. They do not yet authorize or release outbound payloads; that belongs to the gateway vertical slice in Phase 5.

## Verification

The Phase 4 suite covers valid credentials, wrong audience, expiry, workload mismatch, revocation, unknown destinations, path mismatches, TLS requirements, and private-address rejection.

```bash
ruff check .
mypy tracelock_core tracelock_services tests
pytest
```

## Deferred work

Phase 4 does not yet implement a live identity provider, asymmetric key discovery and rotation, policy authorization, gateway proxying, redirect handling during actual transport, persistent destination ownership history, or durable audit evidence. Those controls are intentionally staged for later phases.
