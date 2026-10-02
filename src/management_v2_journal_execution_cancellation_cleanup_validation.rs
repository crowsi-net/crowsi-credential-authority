fn location(
    value: &crate::management_v2_record::ManagementLedgerV2,
    operation_id: &str,
) -> Result<Location, HostError> {
    if let Some(index) = value
        .records
        .iter()
        .position(|item| item.operation.operation_id == operation_id)
    {
        return Ok(Location::Record(index));
    }
    value
        .tombstones
        .iter()
        .position(|item| item.operation.operation_id == operation_id)
        .map(Location::Tombstone)
        .ok_or(HostError::StateInvalid)
}

fn context(
    ledger: &crate::management_v2_record::ManagementLedgerV2,
    location: Location,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    peer: &str,
    now: u64,
) -> Result<Context, HostError> {
    match location {
        Location::Record(index) => record_context(&ledger.records[index], request, peer, now),
        Location::Tombstone(index) => {
            tombstone_context(&ledger.tombstones[index], request, peer, now)
        }
    }
}

fn record_context(
    value: &crate::management_v2_record::ManagementRecordV2,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    peer: &str,
    now: u64,
) -> Result<Context, HostError> {
    if let Some(acceptance) = &value.revocation_finalization {
        return exact(
            &value.operation,
            &value.prepared,
            acceptance.source_approve_request_sha256.as_str(),
            acceptance.response_key_id.as_str(),
            acceptance.response_public_key_hex.as_str(),
            acceptance.minimum_config_generation,
            acceptance.cancellation_slot_reserved,
            acceptance.cancellation_cleanup_completed,
            acceptance.cancellation_cleanup_delivery_completed,
            acceptance.execution_cancellation.as_ref(),
            request,
            peer,
            now,
        );
    }
    let acceptance = value
        .independent_revocation_finalization
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    exact(
        &value.operation,
        &value.prepared,
        acceptance.pre_final_request_sha256.as_str(),
        acceptance.response_key_id.as_str(),
        acceptance.response_public_key_hex.as_str(),
        acceptance.minimum_config_generation,
        acceptance.cancellation_slot_reserved,
        acceptance.cancellation_cleanup_completed,
        acceptance.cancellation_cleanup_delivery_completed,
        acceptance.execution_cancellation.as_ref(),
        request,
        peer,
        now,
    )
}

fn tombstone_context(
    value: &crate::management_v2_record::ManagementTombstoneV2,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    peer: &str,
    now: u64,
) -> Result<Context, HostError> {
    if let Some(acceptance) = &value.revocation_finalization {
        return exact(
            &value.operation,
            &value.prepared,
            acceptance.source_approve_request_sha256.as_str(),
            acceptance.response_key_id.as_str(),
            acceptance.response_public_key_hex.as_str(),
            acceptance.minimum_config_generation,
            acceptance.cancellation_slot_reserved,
            acceptance.cancellation_cleanup_completed,
            acceptance.cancellation_cleanup_delivery_completed,
            acceptance.execution_cancellation.as_ref(),
            request,
            peer,
            now,
        );
    }
    let acceptance = value
        .independent_revocation_finalization
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    exact(
        &value.operation,
        &value.prepared,
        acceptance.pre_final_request_sha256.as_str(),
        acceptance.response_key_id.as_str(),
        acceptance.response_public_key_hex.as_str(),
        acceptance.minimum_config_generation,
        acceptance.cancellation_slot_reserved,
        acceptance.cancellation_cleanup_completed,
        acceptance.cancellation_cleanup_delivery_completed,
        acceptance.execution_cancellation.as_ref(),
        request,
        peer,
        now,
    )
}

include!("management_v2_journal_execution_cancellation_cleanup_validation_support.rs");
