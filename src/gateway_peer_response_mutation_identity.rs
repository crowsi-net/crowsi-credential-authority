fn live(
    trust: &HostConfigDocument,
    exchange: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    identity: &ihat_identity_assertion_contracts::IdentityEvidenceMetadata,
    now: u64,
) -> bool {
    crowsi_credential_authority_contracts::verify_authority_exchange_at(
        exchange,
        "issue_current_device_identity_evidence",
        trust.minimum_identity_config_generation,
        &trust.identity_response_key_id,
        &trust.identity_response_public_key_hex,
        now,
    )
    .is_ok()
        && crowsi_credential_authority_contracts::verify_endpoint_identity_at(
            identity,
            &EndpointIdentityTrustV2 {
                issuer: &trust.identity_issuer,
                audience: &trust.management_audience,
                assertion_key_id: &trust.identity_key_id,
                assertion_public_key_hex: &trust.identity_public_key_hex,
                current_status_key_id: &trust.current_status_key_id,
                current_status_public_key_hex: &trust.current_status_public_key_hex,
                now_epoch_s: now,
            },
        )
        .is_ok()
}
