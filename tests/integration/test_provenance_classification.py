from datetime import UTC, datetime, timedelta

from tracelock_core.contracts import Classification
from tracelock_services.provenance import (
    ProvenanceLabel,
    TrustedProvenanceVerifier,
    classify_payload,
    issue_provenance_token,
)

KEY = "phase6-provenance-test-key-with-32-bytes!!"
ISSUER = "phase6-provenance-issuer"
AUDIENCE = "phase6-gateway"


def trusted_token(labels: tuple[ProvenanceLabel, ...]) -> str:
    return issue_provenance_token(
        signing_key=KEY,
        issuer=ISSUER,
        audience=AUDIENCE,
        source_integration="approved-source",
        labels=labels,
        jti="provenance-test-jti",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def verifier() -> TrustedProvenanceVerifier:
    return TrustedProvenanceVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        signing_key=KEY,
        approved_integrations={"approved-source"},
    )


def test_signed_provenance_manifest_is_verified() -> None:
    label = ProvenanceLabel(
        field_path="customer.email",
        classification=Classification.CONFIDENTIAL,
        source_resource="crm.customers",
        confidence="high",
    )

    result = verifier().verify(trusted_token((label,)))

    assert result.verified is True
    assert result.reason_code == "verified"
    assert result.labels[0].classification is Classification.CONFIDENTIAL


def test_unapproved_source_and_missing_provenance_are_rejected() -> None:
    label = ProvenanceLabel(
        field_path="customer.email",
        classification=Classification.CONFIDENTIAL,
        source_resource="crm.customers",
        confidence="high",
    )
    unapproved = TrustedProvenanceVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        signing_key=KEY,
        approved_integrations={"different-source"},
    ).verify(trusted_token((label,)))

    assert unapproved.reason_code == "unapproved_source_integration"
    assert verifier().verify("").reason_code == "missing_provenance"


def test_unknown_or_renamed_fields_are_not_silently_downgraded() -> None:
    label = ProvenanceLabel(
        field_path="customer.email",
        classification=Classification.CONFIDENTIAL,
        source_resource="crm.customers",
        confidence="high",
    )

    renamed = classify_payload({"customer": {"email_address": "encoded-value"}}, (label,))
    missing = classify_payload({"customer": {"email": "encoded-value"}}, ())
    encoded_same_path = classify_payload({"customer": {"email": "base64-value"}}, (label,))

    assert "customer.email_address" in renamed.unknown_field_paths
    assert Classification.UNKNOWN in renamed.summary
    assert "customer.email" in missing.unknown_field_paths
    assert Classification.UNKNOWN in missing.summary
    assert encoded_same_path.unknown_field_paths == ()
    assert encoded_same_path.summary == (Classification.CONFIDENTIAL,)
