fn uses<'a>(
    request: &'a EndpointIndependentRevocationPreFinalRequestV1,
    verified: &'a VerifiedManagementIdentity<'a>,
    fresh: &'a ihat_identity_assertion_contracts::FreshUvV1,
    identity_digest: &'a str,
    finish_digest: &'a str,
    approval: &'a ihat_identity_assertion_contracts::SignedEvidenceV1,
    binding: &'a str,
) -> [EvidenceUse<'a>; 6] {
    [
        EvidenceUse {
            kind: "fresh_uv_proof",
            id: &fresh.proof_id,
            binding,
            expires_at_epoch_s: fresh.expires_at_epoch_s,
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
            expires_at_epoch_s: request.finish_uv_exchange.response.expires_at_epoch_s,
        },
        EvidenceUse {
            kind: "revocation_approval_proof",
            id: &approval.proof_id,
            binding,
            expires_at_epoch_s: approval.expires_at_epoch_s,
        },
    ]
}
