#[allow(clippy::too_many_arguments)]
fn exact(
    operation: &crowsi_credential_authority_contracts::ManagementOperationV2,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    pre_final_digest: &str,
    response_key_id: &str,
    response_public_key_hex: &str,
    minimum_config_generation: u64,
    slot: bool,
    completed: bool,
    delivery_completed: bool,
    stored: Option<&crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1>,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    peer: &str,
    now: u64,
) -> Result<Context, HostError> {
    let stored = stored.ok_or(HostError::StateInvalid)?;
    let cancellation = stored.cancellation.as_ref();
    let valid = operation.state
        == crowsi_credential_authority_contracts::ManagementOperationState::Cancelled
        && operation == &cancellation.operation
        && prepared == &request.cancellation_request.prepared
        && peer == prepared.source_device_ref
        && pre_final_digest
            == request
                .cancellation_request
                .pre_final_acceptance_request_sha256
        && stored.cancellation_request.as_ref() == request.cancellation_request.as_ref()
        && stored.cancellation_request_sha256
            == crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_request_digest(
                &request.cancellation_request,
            )
            .map_err(|_| HostError::RequestInvalid)?
        && request.cancellation.cancellation_id == cancellation.cancellation_id
        && request.cancellation.token == cancellation.token
        && request.cancellation.cancellation_request_sha256
            == cancellation.cancellation_request_sha256
        && cancellation.source_device_ref == peer
        && cancellation.execution_reservation_id.is_none();
    if !valid {
        return Err(HostError::StateInvalid);
    }
    crowsi_credential_authority_contracts::verify_endpoint_revocation_execution_cancel_response_historic_at(
        request,
        cancellation,
        &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelResponseTrustV1 {
            key_id: response_key_id,
            public_key_hex: response_public_key_hex,
            minimum_config_generation,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::EvidenceInvalid)?;
    let cleanup = stored_cleanup(stored, request)?;
    let phase_valid = if cleanup.is_some() {
        completed && (slot != delivery_completed)
    } else {
        slot && !completed && !delivery_completed
    };
    phase_valid
        .then_some(Context {
            operation: operation.clone(),
            stored: cleanup,
        })
        .ok_or(HostError::StateInvalid)
}

fn stored_cleanup(
    value: &crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
) -> Result<Option<EndpointRevocationExecutionCancellationCleanupV1>, HostError> {
    match (
        value.cleanup_accepted_at_epoch_s,
        &value.cleanup_request_sha256,
        &value.cleanup_request,
        &value.cleanup,
        &value.cleanup_exchange,
    ) {
        (None, None, None, None, None) => Ok(None),
        (Some(_), Some(digest), Some(stored), Some(cleanup), Some(exchange)) => {
            let request_digest = crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_finalize_request_digest(request)
                .map_err(|_| HostError::RequestInvalid)?;
            (digest == &request_digest
                && stored.as_ref() == request
                && exchange == &request.cancel_pending_exchange)
                .then(|| Some(cleanup.as_ref().clone()))
                .ok_or(HostError::StateInvalid)
        }
        _ => Err(HostError::StateInvalid),
    }
}
