fn fresh(
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    identity: &ihat_identity_assertion_contracts::IdentityEvidenceMetadata,
) -> FreshUvV1 {
    let epochs = &identity.assertion.revocation_epochs;
    FreshUvV1 {
        schema: FRESH_UV_SCHEMA.into(),
        proof_id: "fresh-proof".into(),
        credential_id: "credential-source".into(),
        authenticator_key_fingerprint: "77".repeat(32),
        kind: AuthenticatorKindDto::DeviceBoundPasskey,
        user_verified: true,
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 100,
        challenge: "challenge".into(),
        attempt_id: "attempt-source".into(),
        identity_nonce: identity.assertion.nonce.clone(),
        source_device_id: DEVICE.into(),
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        session_ref: prepared.source_session_ref.clone(),
        operation_digest_sha256: crowsi_credential_authority_contracts::endpoint_operation_digest(
            prepared,
        )
        .expect("operation digest"),
        subject_epoch: epochs.subject,
        service_epoch: epochs.service,
        device_epoch: epochs.device,
        session_epoch: epochs.session,
        account_binding_sha256: "55".repeat(32),
        key_id: "fresh-key".into(),
        signature: "11".repeat(64),
    }
}

fn authentication(value: &FreshUvV1) -> FreshAuthenticationDto {
    FreshAuthenticationDto {
        proof_id: value.proof_id.clone(),
        authenticator_id: value.credential_id.clone(),
        authenticator_key_fingerprint: value.authenticator_key_fingerprint.clone(),
        kind: value.kind,
        user_verified: value.user_verified,
        issued_at_epoch_s: value.issued_at_epoch_s,
        expires_at_epoch_s: value.expires_at_epoch_s,
        service_id: value.service_id.clone(),
        pairwise_subject: value.pairwise_subject.clone(),
        session_ref: value.session_ref.clone(),
        operation_digest_sha256: value.operation_digest_sha256.clone(),
        subject_epoch: value.subject_epoch,
        service_epoch: value.service_epoch,
        device_epoch: value.device_epoch,
        session_epoch: value.session_epoch,
    }
}

fn signed_exchange(
    request_id: &str,
    command: AuthorityCommand,
    evidence: Vec<AuthorityEvidence>,
    result: AuthorityResult,
    issued_at: u64,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: request_id.into(),
        command,
        evidence,
    };
    let digest = command_digest(&request).expect("command digest");
    for item in &mut request.evidence {
        if let AuthorityEvidence::Signed(item) = item {
            item.binding_sha256.clone_from(&digest);
        }
    }
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request_id.into(),
        command_type: request.command.type_name().into(),
        command_digest: digest,
        config_generation: 2,
        issued_at_epoch_s: issued_at,
        expires_at_epoch_s: issued_at + 30,
        outcome: ResponseOutcome::Committed { result },
        key_id: "identity-response-key".into(),
        signature: String::new(),
    };
    response.signature = hex::encode(
        crate::gateway_peer_response_identity::key(5)
            .sign(&canonical_response(&response).expect("response canonical"))
            .to_bytes(),
    );
    crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 { request, response }
}
