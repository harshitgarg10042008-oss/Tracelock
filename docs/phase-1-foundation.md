# Phase 1 Foundation

## Decision

TraceLock begins as a framework-independent Python domain package. The first package contains stable contracts for workload identity, destination identity, field classification, request context, and privacy-preserving decisions.

Infrastructure adapters, network routing, credential verification, persistence, and user interfaces are deferred until the phases that require them.

## Rationale

A security product needs stable semantics before it needs a large runtime. Defining the domain contracts first lets later gateway, policy, storage, and dashboard components share the same vocabulary and prevents transport details from silently changing the meaning of an authorization decision.

## Protected boundary for the MVP

The MVP protects forced HTTP/JSON egress from registered workloads to registered destinations. It does not claim to protect traffic that bypasses the gateway or unsupported protocols and payload formats.

## Security invariants introduced in Phase 1

- A decision has a stable request ID, decision ID, policy ID, and policy version.
- A decision records enforcement and receiver status separately.
- A decision may contain field paths and classifications but never a raw payload.
- Unknown classification is a first-class value, not an absent field.
- Domain contracts do not authorize traffic by themselves; release enforcement arrives in later phases.

## Deferred decisions

The following are intentionally deferred:

- The concrete gateway framework and transport implementation.
- Workload credential format and cryptographic verification.
- Destination DNS, TLS, redirect, and private-address enforcement.
- Provenance signing and source adapters.
- Policy syntax, precedence, signing, and rollout.
- Redaction implementation and transformed-payload validation.
- Database, event integrity chain, and dashboard.
- Production high availability and disaster recovery.

## Exit review

Phase 1 is ready for review when the package installs from a clean clone, the contract tests pass, static quality checks pass, and the repository’s boundary and non-goals are documented in the README.
