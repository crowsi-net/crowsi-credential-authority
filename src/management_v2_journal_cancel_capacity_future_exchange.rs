use ihat_identity_assertion_contracts::{
    AUTHORITY_RESPONSE_SCHEMA, AuthorityResponseV1, AuthorityResult,
    PendingCancellationAcknowledgedMetadata, PendingRevocationCancelledMetadata, ResponseOutcome,
    command_digest,
};

fn maximum_cancel_exchange(
    cancellation: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationV1,
    begin_key_id: &str,
) -> Result<SignedAuthorityExchangeV1, HostError> {
    let request = crowsi_credential_authority_contracts::attach_revocation_execution_cancellation(
        &cancellation.cancel_pending_request,
        cancellation,
    )
    .map_err(|_| HostError::StateInvalid)?;
    let ihat_identity_assertion_contracts::AuthorityCommand::CancelPendingRevocation(command) =
        &request.command
    else {
        return Err(HostError::StateInvalid);
    };
    let response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: command_digest(&request).map_err(|_| HostError::StateInvalid)?,
        config_generation: u64::MAX,
        issued_at_epoch_s: CAPACITY_TIME,
        expires_at_epoch_s: CAPACITY_TIME + 30,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::PendingRevocationCancelled(
                PendingRevocationCancelledMetadata {
                    attempt_id: command.attempt_id.clone(),
                    finalize_command_id: command.finalize_command_id.clone(),
                    target_digest_sha256: command.target_digest_sha256.clone(),
                    cancellation_id: cancellation.cancellation_id.clone(),
                },
            ),
        },
        key_id: begin_key_id.into(),
        signature: "f".repeat(128),
    };
    Ok(SignedAuthorityExchangeV1 { request, response })
}

fn maximum_acknowledgement_exchange(
    cleanup: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupV1,
) -> Result<SignedAuthorityExchangeV1, HostError> {
    let request = crowsi_credential_authority_contracts::attach_revocation_cancellation_cleanup(
        &cleanup.acknowledge_request,
        cleanup,
    )
    .map_err(|_| HostError::StateInvalid)?;
    let response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: command_digest(&request).map_err(|_| HostError::StateInvalid)?,
        config_generation: u64::MAX,
        issued_at_epoch_s: CAPACITY_TIME,
        expires_at_epoch_s: CAPACITY_TIME + 30,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::PendingCancellationAcknowledged(
                PendingCancellationAcknowledgedMetadata {
                    cancellation_id: cleanup.cancellation_id.clone(),
                    cleanup_id: cleanup.cleanup_id.clone(),
                },
            ),
        },
        key_id: maximum_id(2),
        signature: "f".repeat(128),
    };
    Ok(SignedAuthorityExchangeV1 { request, response })
}
