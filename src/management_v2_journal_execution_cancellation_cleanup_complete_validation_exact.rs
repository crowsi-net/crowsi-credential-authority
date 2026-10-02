#[allow(clippy::too_many_arguments)]
fn exact(
    operation: &crowsi_credential_authority_contracts::ManagementOperationV2,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    slot: bool,
    cleanup_completed: bool,
    delivery_completed: bool,
    stored: Option<&crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1>,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    peer: &str,
    config: &VerifiedHostConfig,
    now: u64,
) -> Result<Context, HostError> {
    let stored = stored.ok_or(HostError::StateInvalid)?;
    let cleanup_request = stored
        .cleanup_request
        .as_deref()
        .ok_or(HostError::StateInvalid)?;
    let cleanup = stored.cleanup.as_deref().ok_or(HostError::StateInvalid)?;
    let valid = operation.state
        == crowsi_credential_authority_contracts::ManagementOperationState::Cancelled
        && operation == &request.cleanup.operation
        && prepared
            == &request
                .cancel_finalize_request
                .cancellation_request
                .prepared
        && peer == prepared.source_device_ref
        && cleanup_request == request.cancel_finalize_request.as_ref()
        && cleanup.cleanup_id == request.cleanup.cleanup_id
        && cleanup.token == request.cleanup.token
        && stored.cancellation.cancellation_id
            == request.cancel_finalize_request.cancellation.cancellation_id
        && stored.cancellation.cancellation_request_sha256
            == request
                .cancel_finalize_request
                .cancellation
                .cancellation_request_sha256
        && stored.cancellation.token == request.cancel_finalize_request.cancellation.token;
    if !valid {
        return Err(HostError::StateInvalid);
    }
    crowsi_credential_authority_contracts::validate_endpoint_revocation_execution_cancel_cleanup_complete_against_acceptance(
        request,
        cleanup,
    )
    .map_err(|_| HostError::RequestInvalid)?;
    crowsi_credential_authority_contracts::verify_endpoint_revocation_execution_cancellation_cleanup_at(
        &request.cleanup,
        cleanup_request,
        &request.cancel_finalize_request.cancellation,
        peer,
        &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupTrustV1 {
            issuer: &config.document.management_projection_issuer,
            audience: &config.document.management_audience,
            key_id: &config.document.management_projection_key_id,
            public_key_hex: &config.document.management_projection_public_key_hex,
            minimum_config_generation: config.document.revocation_execution_reservation_config_generation,
            cleanup_key_id: &config.document.revocation_execution_reservation_key_id,
            cleanup_public_key_hex: &config.document.revocation_execution_reservation_public_key_hex,
            minimum_cleanup_config_generation: config.document.revocation_execution_reservation_config_generation,
            minimum_snapshot_revision: cleanup.snapshot_revision,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::EvidenceInvalid)?;
    crowsi_credential_authority_contracts::verify_endpoint_revocation_cancellation_cleanup_exchange_historic_at(
        &request.acknowledge_exchange,
        cleanup,
        &crowsi_credential_authority_contracts::EndpointRevocationCancellationCleanupResponseTrustV1 {
            key_id: &config.document.identity_response_key_id,
            public_key_hex: &config.document.identity_response_public_key_hex,
            minimum_config_generation: config.document.minimum_identity_config_generation,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::EvidenceInvalid)?;
    let stored = stored_delivery(stored, request)?;
    let phase = if stored.is_some() {
        !slot && cleanup_completed && delivery_completed
    } else {
        slot && cleanup_completed && !delivery_completed
    };
    phase
        .then_some(Context {
            operation: operation.clone(),
            stored,
        })
        .ok_or(HostError::StateInvalid)
}

fn stored_delivery(
    value: &crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
) -> Result<
    Option<Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupCompleteV1>>,
    HostError,
>{
    match (
        value.cleanup_delivery_accepted_at_epoch_s,
        &value.cleanup_delivery_request_sha256,
        &value.cleanup_delivery_request,
        &value.cleanup_delivery,
    ) {
        (None, None, None, None) => Ok(None),
        (Some(_), Some(digest), Some(_), Some(delivery)) => {
            let supplied = crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_cleanup_complete_request_digest(request)
                .map_err(|_| HostError::RequestInvalid)?;
            (digest == &supplied
                && delivery.cleanup_complete_request_sha256 == supplied
                && delivery.cleanup_id == request.cleanup.cleanup_id)
                .then(|| Some(delivery.clone()))
                .ok_or(HostError::StateInvalid)
        }
        _ => Err(HostError::StateInvalid),
    }
}
