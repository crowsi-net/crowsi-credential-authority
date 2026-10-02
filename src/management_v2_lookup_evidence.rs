fn lookup_uses<'a>(
    verified: &'a crate::management_v2_identity::VerifiedManagementIdentity<'a>,
    identity_digest: &'a str,
    request_digest: &'a str,
    exchange_expiry: u64,
) -> [crate::management_v2_journal_update::EvidenceUse<'a>; 3] {
    [
        crate::management_v2_journal_update::EvidenceUse {
            kind: "identity_authority_exchange",
            id: identity_digest,
            binding: request_digest,
            expires_at_epoch_s: exchange_expiry,
        },
        crate::management_v2_journal_update::EvidenceUse {
            kind: "identity_assertion_nonce",
            id: &verified.identity.assertion.nonce,
            binding: request_digest,
            expires_at_epoch_s: verified.identity.assertion.expires_at_epoch_s,
        },
        crate::management_v2_journal_update::EvidenceUse {
            kind: "current_status_nonce",
            id: &verified.identity.current_status.nonce,
            binding: request_digest,
            expires_at_epoch_s: verified.identity.current_status.expires_at_epoch_s,
        },
    ]
}
