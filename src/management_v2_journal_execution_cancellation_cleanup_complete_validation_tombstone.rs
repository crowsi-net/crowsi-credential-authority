fn tombstone_context(
    value: &crate::management_v2_record::ManagementTombstoneV2,
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
