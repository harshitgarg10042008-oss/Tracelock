"""Phase 4 workload credential verification.

The local implementation uses signed JWTs with an explicit algorithm allowlist.
Production deployments must use managed key rotation and a protected issuer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import jwt
from jwt import InvalidTokenError


@dataclass(frozen=True, slots=True)
class IdentityVerification:
    """Privacy-safe outcome of verifying a workload credential."""

    verified: bool
    reason_code: str
    workload_id: str | None = None
    subject: str | None = None
    issuer: str | None = None
    audience: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "reason_code": self.reason_code,
            "workload_id": self.workload_id,
            "subject": self.subject,
            "issuer": self.issuer,
            "audience": self.audience,
        }


class WorkloadCredentialVerifier:
    """Verify short-lived workload credentials for a registered workload."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        signing_key: str,
        workload_subjects: dict[str, str],
        revoked_jti: set[str] | None = None,
        leeway_seconds: int = 0,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.signing_key = signing_key
        self.workload_subjects = dict(workload_subjects)
        self.revoked_jti = set(revoked_jti or set())
        self.leeway_seconds = leeway_seconds

    def verify(self, token: str, *, expected_workload_id: str) -> IdentityVerification:
        """Verify a bearer token without exposing token contents in the result."""

        if not token:
            return IdentityVerification(False, "missing_credential")

        try:
            claims = jwt.decode(
                token,
                self.signing_key,
                algorithms=["HS256"],
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]},
            )
        except InvalidTokenError as error:
            return IdentityVerification(False, self._reason_for_error(error))

        subject = self._claim_string(claims, "sub")
        issuer = self._claim_string(claims, "iss")
        audience = self._audience_string(claims.get("aud"))
        jti = self._claim_string(claims, "jti")
        workload_id = self._claim_string(claims, "workload_id")

        if subject is None or issuer is None or audience is None or jti is None:
            return IdentityVerification(False, "invalid_claim_types")
        if workload_id != expected_workload_id:
            return IdentityVerification(
                False, "wrong_workload", workload_id, subject, issuer, audience
            )
        if self.workload_subjects.get(expected_workload_id) != subject:
            return IdentityVerification(
                False, "unregistered_subject", workload_id, subject, issuer, audience
            )
        if jti in self.revoked_jti:
            return IdentityVerification(
                False, "revoked_credential", workload_id, subject, issuer, audience
            )

        return IdentityVerification(True, "verified", workload_id, subject, issuer, audience)

    @staticmethod
    def _claim_string(claims: dict[str, Any], name: str) -> str | None:
        value = claims.get(name)
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _audience_string(value: Any) -> str | None:
        if isinstance(value, str) and value:
            return value
        return None

    @staticmethod
    def _reason_for_error(error: InvalidTokenError) -> str:
        name = type(error).__name__
        reasons = {
            "ExpiredSignatureError": "expired_credential",
            "ImmatureSignatureError": "not_yet_valid",
            "InvalidIssuerError": "wrong_issuer",
            "InvalidAudienceError": "wrong_audience",
            "MissingRequiredClaimError": "missing_required_claim",
            "InvalidAlgorithmError": "unsupported_algorithm",
        }
        return reasons.get(name, "invalid_credential")


def issue_demo_token(
    *,
    signing_key: str,
    issuer: str,
    audience: str,
    workload_id: str,
    subject: str,
    jti: str,
    expires_at: datetime,
) -> str:
    """Issue a deterministic-shape local token for tests and demonstrations."""

    now = datetime.now(UTC)
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "workload_id": workload_id,
        "jti": jti,
        "iat": now,
        "exp": expires_at,
    }
    encoded = jwt.encode(payload, signing_key, algorithm="HS256")
    return encoded if isinstance(encoded, str) else encoded.decode("utf-8")
