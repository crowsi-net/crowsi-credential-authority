fn store(
    ledger: &mut crate::management_v2_record::ManagementLedgerV2,
    location: Location,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
    config: &crate::host_config::VerifiedHostConfig,
    now: u64,
) -> Result<(), HostError> {
    match location {
        Location::Record(index) => {
            store_record(&mut ledger.records[index], request, cleanup, config, now)
        }
        Location::Tombstone(index) => {
            store_tombstone(&mut ledger.tombstones[index], request, cleanup, config, now)
        }
    }
}

fn store_record(
    value: &mut crate::management_v2_record::ManagementRecordV2,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
    config: &crate::host_config::VerifiedHostConfig,
    now: u64,
) -> Result<(), HostError> {
    if let Some(item) = &mut value.revocation_finalization {
        return store_acceptance(
            &mut item.cancellation_slot_reserved,
            &mut item.cancellation_cleanup_completed,
            item.execution_cancellation.as_mut(),
            request,
            cleanup,
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
        &mut item.cancellation_cleanup_completed,
        item.execution_cancellation.as_mut(),
        request,
        cleanup,
        config,
        now,
    )
}

fn store_tombstone(
    value: &mut crate::management_v2_record::ManagementTombstoneV2,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
    config: &crate::host_config::VerifiedHostConfig,
    now: u64,
) -> Result<(), HostError> {
    if let Some(item) = &mut value.revocation_finalization {
        return store_acceptance(
            &mut item.cancellation_slot_reserved,
            &mut item.cancellation_cleanup_completed,
            item.execution_cancellation.as_mut(),
            request,
            cleanup,
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
        &mut item.cancellation_cleanup_completed,
        item.execution_cancellation.as_mut(),
        request,
        cleanup,
        config,
        now,
    )
}

fn store_acceptance(
    slot: &mut bool,
    completed: &mut bool,
    value: Option<&mut crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1>,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
    config: &crate::host_config::VerifiedHostConfig,
    now: u64,
) -> Result<(), HostError> {
    let value = value.ok_or(HostError::StateInvalid)?;
    if !*slot || *completed || value.cleanup.is_some() {
        return Err(HostError::StateInvalid);
    }
    value.cleanup_accepted_at_epoch_s = Some(now);
    value.cleanup_outer_key_id = Some(config.document.management_projection_key_id.clone());
    value.cleanup_outer_public_key_hex =
        Some(config.document.management_projection_public_key_hex.clone());
    value.cleanup_outer_config_generation = Some(cleanup.config_generation);
    value.cleanup_request_sha256 = Some(
        crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_finalize_request_digest(request)
            .map_err(|_| HostError::RequestInvalid)?,
    );
    value.cleanup_request = Some(Box::new(request.clone()));
    value.cleanup_exchange = Some(request.cancel_pending_exchange.clone());
    value.cleanup = Some(Box::new(cleanup.clone()));
    *slot = true;
    *completed = true;
    Ok(())
}
