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
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    peer: &str,
    config: &VerifiedHostConfig,
    now: u64,
) -> Result<Context, HostError> {
    match location {
        Location::Record(index) => {
            record_context(&ledger.records[index], request, peer, config, now)
        }
        Location::Tombstone(index) => {
            tombstone_context(&ledger.tombstones[index], request, peer, config, now)
        }
    }
}

fn record_context(
    value: &crate::management_v2_record::ManagementRecordV2,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    peer: &str,
    config: &VerifiedHostConfig,
    now: u64,
) -> Result<Context, HostError> {
    if let Some(item) = &value.revocation_finalization {
        return exact(
            &value.operation,
            &value.prepared,
            item.cancellation_slot_reserved,
            item.cancellation_cleanup_completed,
            item.cancellation_cleanup_delivery_completed,
            item.execution_cancellation.as_ref(),
            request,
            peer,
            config,
            now,
        );
    }
    let item = value
        .independent_revocation_finalization
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    exact(
        &value.operation,
        &value.prepared,
        item.cancellation_slot_reserved,
        item.cancellation_cleanup_completed,
        item.cancellation_cleanup_delivery_completed,
        item.execution_cancellation.as_ref(),
        request,
        peer,
        config,
        now,
    )
}

include!("management_v2_journal_execution_cancellation_cleanup_complete_validation_tombstone.rs");
include!("management_v2_journal_execution_cancellation_cleanup_complete_validation_exact.rs");
