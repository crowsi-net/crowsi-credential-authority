fn begin(
    prepared: &EndpointPreparedOperationV2,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    use ihat_identity_assertion_contracts::{
        AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AuthorityCommand, AuthorityRequestV1,
        AuthorityResponseV1, AuthorityResult, BeginFreshUvCommand, FreshUvRequestOptions,
        ResponseOutcome, command_digest,
    };
    let request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "begin-recovery".into(),
        command: AuthorityCommand::BeginFreshUserVerification(BeginFreshUvCommand {
            command_id: "begin-command".into(),
            credential_id: "credential-a".into(),
            identity_nonce: prepared.source_identity_nonce.clone(),
            source_device_id: prepared.source_device_ref.clone(),
            service_id: "service-a".into(),
            pairwise_subject: prepared.pairwise_subject.clone(),
            session_ref: prepared.source_session_ref.clone(),
            operation_digest_sha256:
                crowsi_credential_authority_contracts::endpoint_operation_digest(prepared)
                    .expect("operation digest"),
            subject_epoch: 1,
            service_epoch: 2,
            device_epoch: 3,
            session_epoch: 4,
        }),
        evidence: Vec::new(),
    };
    let options = FreshUvRequestOptions {
        attempt_id: "attempt-a".into(),
        challenge: "Y2hhbGxlbmdl".into(),
        rp_id: "example.test".into(),
        origin: "https://example.test".into(),
        credential_id: "credential-a".into(),
        timeout_ms: 120_000,
        expires_at_epoch_s: NOW + 120,
        command_binding_sha256: command_digest(&request).expect("command digest"),
    };
    let response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: command_digest(&request).expect("response digest"),
        config_generation: 2,
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 30,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvBegun(options),
        },
        key_id: "identity-response-key".into(),
        signature: "44".repeat(64),
    };
    crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 { request, response }
}

fn operation(
    prepared: &EndpointPreparedOperationV2,
    begin: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> ManagementOperationV2 {
    let ihat_identity_assertion_contracts::ResponseOutcome::Committed {
        result: ihat_identity_assertion_contracts::AuthorityResult::FreshUvBegun(options),
    } = &begin.response.outcome
    else {
        unreachable!()
    };
    ManagementOperationV2 {
        operation_id: prepared.operation_id.clone(),
        kind: ManagementOperationKind::DeviceTransfer,
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingSourceUv,
        state_revision: 1,
        created_at_epoch_s: NOW,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: prepared.source_device_ref.clone(),
        scope: ManagementOperationScopeV2::DeviceTransfer {
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-a".into()],
            expected_source_device_revocation_epoch: 3,
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::SourceDevice,
            required_actor_device_ref: Some(prepared.source_device_ref.clone()),
            required_approval_authority_ref: None,
            excluded_actor_device_refs: Vec::new(),
        },
        webauthn_options: Some(WebAuthnOptionsV2 {
            attempt_id: options.attempt_id.clone(),
            challenge: options.challenge.clone(),
            rp_id: options.rp_id.clone(),
            origin: options.origin.clone(),
            credential_id: options.credential_id.clone(),
            timeout_ms: options.timeout_ms,
            expires_at_epoch_s: options.expires_at_epoch_s,
            command_binding_sha256: options.command_binding_sha256.clone(),
        }),
        reason: None,
        reconcile_digest: None,
    }
}

pub(crate) fn projection(
    request: &ManagementRequestV2,
    identity: &ihat_identity_assertion_contracts::IdentityEvidenceMetadata,
    operation: ManagementOperationV2,
    revision: u64,
    issued: u64,
    key: u8,
) -> ManagementProjectionV2 {
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let mut value = ManagementProjectionV2 {
        schema: MANAGEMENT_PROJECTION_SCHEMA.into(),
        projection_id: format!("projection-{revision}-{issued}"),
        request_id: request.request_id.clone(),
        command_digest_sha256: management_command_digest(request).expect("digest"),
        issuer: "projection-issuer".into(),
        audience: "management-audience".into(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: assertion.pairwise_subject.clone(),
        opaque_account_ref: OWNER.into(),
        current_device_ref: assertion.device_id.clone(),
        current_session_ref: assertion.session_ref.clone(),
        subject_revocation_epoch: epochs.subject,
        service_revocation_epoch: epochs.service,
        device_revocation_epoch: epochs.device,
        session_revocation_epoch: epochs.session,
        device_posture_state: assertion.device_posture.state.clone(),
        device_posture_revision: assertion.device_posture.revision,
        device_proof_key_ref: assertion.device_proof_key_ref.clone(),
        snapshot_revision: revision,
        issued_at_epoch_s: issued,
        expires_at_epoch_s: issued + 30,
        body: ManagementProjectionBodyV2::Operation { operation },
        key_id: if key == 7 {
            "projection-key".into()
        } else {
            "projection-key-rotated".into()
        },
        signature: String::new(),
    };
    value.signature = hex::encode(
        crate::gateway_peer_response_identity::key(key)
            .sign(&canonical_management_projection(&value).expect("canonical"))
            .to_bytes(),
    );
    value
}
