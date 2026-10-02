#[allow(clippy::too_many_arguments)]
fn independent_uses<'a>(
    verified: &'a VerifiedManagementIdentity<'a>,
    fresh_id: &'a str,
    fresh_expiry: u64,
    finish_digest: &'a str,
    finish_expiry: u64,
    approval_id: &'a str,
    approval_expiry: u64,
    identity_digest: &'a str,
    binding: &'a str,
) -> [EvidenceUse<'a>; 6] {
    [
        EvidenceUse {
            kind: "fresh_uv_proof",
            id: fresh_id,
            binding,
            expires_at_epoch_s: fresh_expiry,
        },
        EvidenceUse {
            kind: "identity_authority_exchange",
            id: identity_digest,
            binding,
            expires_at_epoch_s: verified.identity_exchange.response.expires_at_epoch_s,
        },
        EvidenceUse {
            kind: "identity_assertion_nonce",
            id: &verified.identity.assertion.nonce,
            binding,
            expires_at_epoch_s: verified.identity.assertion.expires_at_epoch_s,
        },
        EvidenceUse {
            kind: "current_status_nonce",
            id: &verified.identity.current_status.nonce,
            binding,
            expires_at_epoch_s: verified.identity.current_status.expires_at_epoch_s,
        },
        EvidenceUse {
            kind: "fresh_uv_finish_exchange",
            id: finish_digest,
            binding,
            expires_at_epoch_s: finish_expiry,
        },
        EvidenceUse {
            kind: "revocation_approval_proof",
            id: approval_id,
            binding,
            expires_at_epoch_s: approval_expiry,
        },
    ]
}
