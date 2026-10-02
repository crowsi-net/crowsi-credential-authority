fn source_request(operation_id: &str) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: crowsi_credential_authority_contracts::MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: "browser-source-approve".into(),
        command: ManagementCommandV2::SourceApprove {
            operation_id: operation_id.into(),
            expected_state_revision: 1,
            attempt_id: "attempt-source".into(),
            assertion: WebAuthnAssertionV2 {
                credential_id: "credential-source".into(),
                client_data_json_base64url: "e30".into(),
                authenticator_data_base64url: "AA".into(),
                signature_der_base64url: "MA".into(),
            },
        },
    }
}

fn configure_record(
    value: &mut ManagementRecordV2,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    identity: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    finish: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    source_request: &ManagementRequestV2,
    begin: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) {
    value.prepared = prepared.clone();
    value.owner_ref = OWNER.into();
    value.service_id = "service-a".into();
    value
        .pairwise_subject
        .clone_from(&prepared.pairwise_subject);
    value.authority_config_generation = 2;
    value.source_identity_exchange = identity.clone();
    value.source_options_exchange = identity.clone();
    value.source_finish_uv_exchange = Some(finish.clone());
    value.source_approval_identity_exchange = Some(identity.clone());
    value.source_revocation_ceremony = Some(RevocationSourceCeremonyV1 {
        begin: begin.clone(),
        final_revoke: None,
    });
    value
        .operation
        .operation_id
        .clone_from(&prepared.operation_id);
    value
        .operation
        .intent_digest_sha256
        .clone_from(&prepared.origin_command_digest_sha256);
    value.operation.state = ManagementOperationState::AwaitingRevocationFinal;
    value.operation.state_revision = 2;
    value.operation.created_at_epoch_s = NOW;
    value.operation.expires_at_epoch_s = prepared.expires_at_epoch_s;
    value.operation.source_device_ref = DEVICE.into();
    value.operation.scope = ManagementOperationScopeV2::DeviceRevocation {
        target_device_ref: DEVICE.into(),
        expected_device_revocation_epoch: 1,
        revokes_session_refs: vec!["session-revoked".into()],
        rotates_credential_refs: Vec::new(),
        preserves_device_refs: Vec::new(),
    };
    value.operation.actor = ActorRequirementV2 {
        role: RequiredActorRole::ReconcileOnly,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    };
    value.operation.webauthn_options = None;
    value.operation.reason = None;
    value.operation.reconcile_digest = Some("44".repeat(32));
    let _ = source_request;
}

fn source_envelope(
    record: &ManagementRecordV2,
    request: &ManagementRequestV2,
    identity: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    finish: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    begin: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> EndpointManagementEnvelopeV2 {
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: request.clone(),
        evidence: EndpointManagementEvidenceV2::SourceApprove {
            identity_exchange: identity.clone(),
            prepared: record.prepared.clone(),
            finish_uv_exchange: finish.clone(),
            revocation_ceremony: Some(RevocationSourceCeremonyV1 {
                begin: begin.clone(),
                final_revoke: None,
            }),
        },
    }
}

fn acceptance(
    source_request: &ManagementRequestV2,
    identity: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    begin: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    phase: String,
) -> RevocationFinalizationAcceptanceV1 {
    RevocationFinalizationAcceptanceV1 {
        accepted_at_epoch_s: NOW,
        pre_final_state_revision: 2,
        pre_final_snapshot_revision: 2,
        source_approve_request_sha256: phase,
        reconcile_digest: "44".repeat(32),
        source_approve_request: source_request.clone(),
        accepted_identity_exchange: identity.clone(),
        begin_exchange: begin.clone(),
        response_key_id: "identity-response-key".into(),
        response_public_key_hex: crate::gateway_peer_response_identity::public(5),
        minimum_config_generation: 2,
        cancellation_slot_reserved: false,
        cancellation_cleanup_completed: false,
        cancellation_cleanup_delivery_completed: false,
        cancellation_recovery_reservation_bytes: 0,
        execution_reservation: None,
        execution_cancellation: None,
        finalize_request_sha256: None,
        finalize_request: None,
        final_revoke_exchange: None,
    }
}
