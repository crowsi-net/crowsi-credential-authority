fn store_tombstone(
    value: &mut crate::management_v2_record::ManagementTombstoneV2,
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
