fn stored(
    ledger: &crate::management_v2_record::ManagementLedgerV2,
    location: Location,
    request: &EndpointRevocationExecutionCancelRequestV1,
) -> Result<Option<EndpointRevocationExecutionCancellationV1>, HostError> {
    let (self_value, independent) = acceptances(ledger, location);
    let value = self_value
        .and_then(|item| item.execution_cancellation.as_ref())
        .or_else(|| independent.and_then(|item| item.execution_cancellation.as_ref()));
    let Some(value) = value else {
        return Ok(None);
    };
    (value.cancellation_request.as_ref() == request
        && value.cancellation_request_sha256
            == crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_request_digest(request)
                .map_err(|_| HostError::RequestInvalid)?)
        .then(|| value.cancellation.as_ref().clone())
        .ok_or(HostError::StateInvalid)
        .map(Some)
}

fn acceptance(
    config: &VerifiedHostConfig,
    request: &EndpointRevocationExecutionCancelRequestV1,
    cancellation: &EndpointRevocationExecutionCancellationV1,
    now: u64,
) -> Result<crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1, HostError> {
    Ok(crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1 {
        accepted_at_epoch_s: now,
        outer_key_id: config.document.management_projection_key_id.clone(),
        outer_public_key_hex: config.document.management_projection_public_key_hex.clone(),
        outer_config_generation: cancellation.config_generation,
        cancellation_key_id: config.document.revocation_execution_reservation_key_id.clone(),
        cancellation_public_key_hex: config
            .document
            .revocation_execution_reservation_public_key_hex
            .clone(),
        cancellation_config_generation: config
            .document
            .revocation_execution_reservation_config_generation,
        cancellation_request_sha256: crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_request_digest(request)
            .map_err(|_| HostError::RequestInvalid)?,
        cancellation_request: Box::new(request.clone()),
        cancellation: Box::new(cancellation.clone()),
        cleanup_exchange: None,
        cleanup_accepted_at_epoch_s: None,
        cleanup_outer_key_id: None,
        cleanup_outer_public_key_hex: None,
        cleanup_outer_config_generation: None,
        cleanup_request_sha256: None,
        cleanup_request: None,
        cleanup: None,
        cleanup_delivery_accepted_at_epoch_s: None,
        cleanup_delivery_outer_key_id: None,
        cleanup_delivery_outer_public_key_hex: None,
        cleanup_delivery_outer_config_generation: None,
        cleanup_delivery_acknowledge_key_id: None,
        cleanup_delivery_acknowledge_public_key_hex: None,
        cleanup_delivery_acknowledge_minimum_config_generation: None,
        cleanup_delivery_request_sha256: None,
        cleanup_delivery_request: None,
        cleanup_delivery: None,
    })
}

fn store(
    ledger: &mut crate::management_v2_record::ManagementLedgerV2,
    location: Location,
    request: &EndpointRevocationExecutionCancelRequestV1,
    value: crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
) -> Result<(), HostError> {
    match location {
        Location::Record(index) => store_record(&mut ledger.records[index], request, value),
        Location::Tombstone(index) => {
            store_tombstone(&mut ledger.tombstones[index], request, value)
        }
    }
}

fn store_record(
    record: &mut crate::management_v2_record::ManagementRecordV2,
    request: &EndpointRevocationExecutionCancelRequestV1,
    value: crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
) -> Result<(), HostError> {
    if let Some(item) = &mut record.revocation_finalization
        && item.source_approve_request_sha256 == request.pre_final_acceptance_request_sha256
    {
        item.execution_cancellation = Some(value);
        return Ok(());
    }
    if let Some(item) = &mut record.independent_revocation_finalization
        && item.pre_final_request_sha256 == request.pre_final_acceptance_request_sha256
    {
        item.execution_cancellation = Some(value);
        return Ok(());
    }
    Err(HostError::StateInvalid)
}

fn store_tombstone(
    record: &mut crate::management_v2_record::ManagementTombstoneV2,
    request: &EndpointRevocationExecutionCancelRequestV1,
    value: crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
) -> Result<(), HostError> {
    if let Some(item) = &mut record.revocation_finalization
        && item.source_approve_request_sha256 == request.pre_final_acceptance_request_sha256
    {
        item.execution_cancellation = Some(value);
        return Ok(());
    }
    if let Some(item) = &mut record.independent_revocation_finalization
        && item.pre_final_request_sha256 == request.pre_final_acceptance_request_sha256
    {
        item.execution_cancellation = Some(value);
        return Ok(());
    }
    Err(HostError::StateInvalid)
}
