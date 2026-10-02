fn request_digest(
    value: &EndpointRevocationExecutionCancelFinalizeRequestV1,
) -> Result<String, HostError> {
    crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_finalize_request_digest(
        value,
    )
    .map_err(|_| HostError::RequestInvalid)
}

fn authority_command_digest(
    value: &EndpointRevocationExecutionCancelFinalizeRequestV1,
) -> Result<String, HostError> {
    command_digest(&value.cancel_pending_exchange.request).map_err(|_| HostError::RequestInvalid)
}

fn response_digest(
    value: &EndpointRevocationExecutionCancelFinalizeRequestV1,
) -> Result<String, HostError> {
    crowsi_credential_authority_contracts::endpoint_signed_authority_exchange_digest(
        &value.cancel_pending_exchange,
    )
    .map_err(|_| HostError::RequestInvalid)
}

fn authority_request(
    config: &VerifiedHostConfig,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    request_digest: &str,
    command_digest: &str,
    response_digest: &str,
    cleanup_revision: u64,
) -> AuthorityRequestV1 {
    AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command: AuthorityCommand::AcknowledgePendingCancellation(
            AcknowledgePendingCancellationCommand {
                command_id: request_digest.into(),
                cancellation_id: request.cancellation.cancellation_id.clone(),
                cancel_pending_command_digest_sha256: command_digest.into(),
                cancel_pending_response_digest_sha256: response_digest.into(),
                source_device_id: request
                    .cancellation_request
                    .prepared
                    .source_device_ref
                    .clone(),
                cleanup_completed_revision: cleanup_revision,
                authority_id: config
                    .document
                    .revocation_execution_reservation_key_id
                    .clone(),
            },
        ),
        evidence: Vec::new(),
    }
}

fn empty_token(config: &VerifiedHostConfig, now: u64) -> SignedEvidenceV1 {
    SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::RevocationCancellationCleanup,
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
    value: &mut EndpointRevocationExecutionCancellationCleanupV1,
) -> Result<(), HostError> {
    value.cleanup_id = crowsi_credential_authority_contracts::endpoint_revocation_execution_cancellation_cleanup_id(value)
        .map_err(|_| HostError::ResponseInvalid)?;
    value.token.proof_id.clone_from(&value.cleanup_id);
    value.token.binding_sha256 =
        command_digest(&value.acknowledge_request).map_err(|_| HostError::ResponseInvalid)?;
    value.token.signature = crate::host_crypto::sign(
        &config.revocation_execution_reservation_signing_key,
        &canonical_signed_evidence(&value.token).map_err(|_| HostError::ResponseInvalid)?,
    );
    value.signature = crate::host_crypto::sign(
        &config.management_projection_signing_key,
        &crowsi_credential_authority_contracts::canonical_endpoint_revocation_execution_cancellation_cleanup(value)
            .map_err(|_| HostError::ResponseInvalid)?,
    );
    Ok(())
}
