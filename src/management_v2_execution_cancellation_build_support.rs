fn cancel_identity(
    value: &EndpointRevocationExecutionCancelRequestV1,
) -> Result<&ihat_identity_assertion_contracts::IdentityEvidenceMetadata, HostError> {
    let EndpointManagementEvidenceV2::Cancel {
        identity_exchange, ..
    } = &value.cancel_envelope.evidence
    else {
        return Err(HostError::RequestInvalid);
    };
    crowsi_credential_authority_contracts::identity_evidence_from_exchange(identity_exchange)
        .map_err(|_| HostError::EvidenceInvalid)
}

fn begun(
    value: &EndpointRevocationExecutionCancelRequestV1,
) -> Result<&ihat_identity_assertion_contracts::RevocationCeremonyMetadata, HostError> {
    match &value.begin_exchange.response.outcome {
        ihat_identity_assertion_contracts::ResponseOutcome::Committed {
            result: ihat_identity_assertion_contracts::AuthorityResult::RevocationBegun(result),
        } => Ok(result),
        _ => Err(HostError::EvidenceInvalid),
    }
}

fn authority_request(
    config: &VerifiedHostConfig,
    request: &EndpointRevocationExecutionCancelRequestV1,
    identity: &ihat_identity_assertion_contracts::IdentityEvidenceMetadata,
    begun: &ihat_identity_assertion_contracts::RevocationCeremonyMetadata,
) -> Result<AuthorityRequestV1, HostError> {
    Ok(AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command: AuthorityCommand::CancelPendingRevocation(CancelPendingRevocationCommand {
            command_id: request.request_id.clone(),
            finalize_command_id: request.operation_id.clone(),
            attempt_id: begun.attempt_id.clone(),
            opaque_owner_ref: request.prepared.opaque_owner_ref.clone(),
            service_id: identity.assertion.service_id.clone(),
            pairwise_subject: identity.assertion.pairwise_subject.clone(),
            source_device_id: request.prepared.source_device_ref.clone(),
            source_session_ref: request.prepared.source_session_ref.clone(),
            target_digest_sha256: begun.target_digest.clone(),
            begin_command_digest_sha256: command_digest(&request.begin_exchange.request)
                .map_err(|_| HostError::RequestInvalid)?,
            cancelled_state_revision: request.expected_cancelled_state_revision,
            authority_id: config
                .document
                .revocation_execution_reservation_key_id
                .clone(),
        }),
        evidence: Vec::new(),
    })
}

fn empty_token(config: &VerifiedHostConfig, now: u64) -> SignedEvidenceV1 {
    SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::RevocationExecutionCancellation,
        proof_id: String::new(),
        key_id: config
            .document
            .revocation_execution_reservation_key_id
            .clone(),
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(120),
        binding_sha256: String::new(),
        signature: String::new(),
    }
}

fn sign(
    config: &VerifiedHostConfig,
    value: &mut EndpointRevocationExecutionCancellationV1,
) -> Result<(), HostError> {
    value.cancellation_id =
        crowsi_credential_authority_contracts::endpoint_revocation_execution_cancellation_id(value)
            .map_err(|_| HostError::ResponseInvalid)?;
    value.token.proof_id.clone_from(&value.cancellation_id);
    value.token.binding_sha256 =
        command_digest(&value.cancel_pending_request).map_err(|_| HostError::ResponseInvalid)?;
    value.token.signature = crate::host_crypto::sign(
        &config.revocation_execution_reservation_signing_key,
        &canonical_signed_evidence(&value.token).map_err(|_| HostError::ResponseInvalid)?,
    );
    value.signature = crate::host_crypto::sign(
        &config.management_projection_signing_key,
        &crowsi_credential_authority_contracts::canonical_endpoint_revocation_execution_cancellation(value)
            .map_err(|_| HostError::ResponseInvalid)?,
    );
    Ok(())
}
