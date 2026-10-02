fn phase_receipt(
    value: &RecoveryFixture,
    record: &crate::management_v2_record::ManagementRecordV2,
    phase: &str,
    digest: char,
    revision: u64,
    actor: &str,
) -> crate::management_v2_record::DurableResponseReceiptV1 {
    let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(
        crate::gateway_peer_response::identity_exchange(&value.envelope.evidence),
    )
    .expect("identity");
    let mut receipt = value.receipt.clone();
    receipt.request_digest_sha256 = format!("sha256:{}", digest.to_string().repeat(64));
    let identity_digest = if digest == 'd' { 'e' } else { 'f' };
    receipt.identity_exchange_sha256 = format!("sha256:{}", identity_digest.to_string().repeat(64));
    receipt.actor_device_ref = actor.into();
    receipt.phase = Some(phase.into());
    receipt.accepted_ledger_revision = 1;
    receipt.accepted_generation_head = 1;
    receipt.response =
        crate::management_v2_record::DurableResponseV1::Projection(Box::new(projection(
            &value.envelope.browser_request,
            identity,
            record.operation.clone(),
            revision,
            NOW,
            7,
        )));
    receipt
}

fn handler(fixture: &Fixture, key: u8) -> crate::management_v2_handler::ManagementV2Handler {
    let mut document = crate::gateway_peer_response_config::trust();
    if key != 7 {
        document.management_projection_key_id = "projection-key-rotated".into();
        document.management_projection_public_key_hex =
            crate::gateway_peer_response_identity::public(key);
        document.identity_response_key_id = "identity-response-key-rotated".into();
        document.identity_response_public_key_hex =
            crate::gateway_peer_response_identity::public(9);
        document.identity_key_id = "identity-key-rotated".into();
        document.identity_public_key_hex = crate::gateway_peer_response_identity::public(10);
        document.current_status_key_id = "status-key-rotated".into();
        document.current_status_public_key_hex = crate::gateway_peer_response_identity::public(11);
    }
    crate::management_v2_handler::ManagementV2Handler {
        core: crate::management_v2_host_context::ManagementHostContext {
            config: crate::host_config::VerifiedHostConfig {
                document,
                response_signing_key: crate::gateway_peer_response_identity::key(6),
                management_projection_signing_key: crate::gateway_peer_response_identity::key(key),
                revocation_execution_reservation_signing_key:
                    crate::gateway_peer_response_identity::key(12),
            },
        },
        journal: fixture.journal(),
    }
}
