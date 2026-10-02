fn store(
    ledger: &mut crate::management_v2_record::ManagementLedgerV2,
    location: Location,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    complete: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
    config: &VerifiedHostConfig,
    now: u64,
) -> Result<(), HostError> {
    match location {
        Location::Record(index) => {
            store_record(&mut ledger.records[index], request, complete, config, now)
        }
        Location::Tombstone(index) => store_tombstone(
            &mut ledger.tombstones[index],
            request,
            complete,
            config,
            now,
        ),
    }
}

fn store_record(
    value: &mut crate::management_v2_record::ManagementRecordV2,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    complete: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
    config: &VerifiedHostConfig,
    now: u64,
) -> Result<(), HostError> {
    if let Some(item) = &mut value.revocation_finalization {
        return store_acceptance(
            &mut item.cancellation_slot_reserved,
            item.cancellation_cleanup_completed,
            &mut item.cancellation_cleanup_delivery_completed,
            item.execution_cancellation.as_mut(),
            request,
            complete,
            config,
            now,
        );
    }
    let item = value
        .independent_revocation_finalization
        .as_mut()
        .ok_or(HostError::StateInvalid)?;
    store_acceptance(
        &mut item.cancellation_slot_reserved,
        item.cancellation_cleanup_completed,
        &mut item.cancellation_cleanup_delivery_completed,
        item.execution_cancellation.as_mut(),
        request,
        complete,
        config,
        now,
    )
}

include!("management_v2_journal_execution_cancellation_cleanup_complete_store_tombstone.rs");
include!("management_v2_journal_execution_cancellation_cleanup_complete_store_acceptance.rs");
