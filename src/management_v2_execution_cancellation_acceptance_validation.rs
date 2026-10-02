#[allow(clippy::too_many_arguments)]
fn cancellation(
    value: &crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
    pre_final_accepted_at: u64,
    pre_final_digest: &str,
    begin_exchange: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    response_key_id: &str,
    response_public_key_hex: &str,
    minimum_config_generation: u64,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
) -> bool {
    let request = value.cancellation_request.as_ref();
    let cancellation = value.cancellation.as_ref();
    let Ok(digest) =
        crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_request_digest(
            request,
        )
    else {
        return false;
    };
    value.accepted_at_epoch_s >= pre_final_accepted_at
        && value.cancellation_request_sha256 == digest
        && request.pre_final_acceptance_request_sha256 == pre_final_digest
        && request.prepared == *prepared
        && request.begin_exchange == *begin_exchange
        && value.outer_key_id == cancellation.key_id
        && value.outer_config_generation == cancellation.config_generation
        && value.cancellation_key_id == cancellation.token.key_id
        && value.cancellation_config_generation == cancellation.cancellation_config_generation
        && cancellation.operation == *operation
        && cancellation.cancelled_state_revision == operation.state_revision
        && cancellation.execution_reservation_id.is_none()
        && crowsi_credential_authority_contracts::verify_endpoint_revocation_execution_cancellation_historic(
            cancellation,
            request,
            &prepared.source_device_ref,
            &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationHistoricTrustV1 {
                issuer: &cancellation.issuer,
                audience: &cancellation.audience,
                key_id: &value.outer_key_id,
                public_key_hex: &value.outer_public_key_hex,
                minimum_config_generation: value.outer_config_generation,
                cancellation_key_id: &value.cancellation_key_id,
                cancellation_public_key_hex: &value.cancellation_public_key_hex,
                minimum_cancellation_config_generation: value.cancellation_config_generation,
                minimum_snapshot_revision: cancellation.snapshot_revision,
                accepted_at_epoch_s: value.accepted_at_epoch_s,
            },
        )
        .is_ok()
        && response_key_id == begin_exchange.response.key_id
        && !response_public_key_hex.is_empty()
        && minimum_config_generation >= begin_exchange.response.config_generation
}

fn cleanup_phase(
    value: &crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
    slot: bool,
    completed: bool,
    delivery_completed: bool,
    prepared: &EndpointPreparedOperationV2,
) -> bool {
    match (
        value.cleanup_accepted_at_epoch_s,
        &value.cleanup_outer_key_id,
        &value.cleanup_outer_public_key_hex,
        value.cleanup_outer_config_generation,
        &value.cleanup_request_sha256,
        &value.cleanup_request,
        &value.cleanup_exchange,
        &value.cleanup,
    ) {
        (None, None, None, None, None, None, None, None) => {
            slot && !completed && !delivery_completed && delivery_phase(value, false, prepared)
        }
        (
            Some(accepted),
            Some(key_id),
            Some(public_key),
            Some(config_generation),
            Some(digest),
            Some(request),
            Some(exchange),
            Some(cleanup),
        ) => {
            completed
                && (slot != delivery_completed)
                && accepted >= value.accepted_at_epoch_s
                && request.cancel_pending_exchange == *exchange
                && crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_finalize_request_digest(request)
                    .is_ok_and(|item| item == *digest)
                && cleanup_valid(
                    value,
                    request,
                    cleanup,
                    accepted,
                    key_id,
                    public_key,
                    config_generation,
                    prepared,
                )
                && delivery_phase(value, delivery_completed, prepared)
        }
        _ => false,
    }
}

fn cleanup_valid(
    value: &crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
    request: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelFinalizeRequestV1,
    cleanup: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupV1,
    accepted: u64,
    outer_key_id: &str,
    outer_public_key_hex: &str,
    outer_config_generation: u64,
    prepared: &EndpointPreparedOperationV2,
) -> bool {
    crowsi_credential_authority_contracts::verify_endpoint_revocation_execution_cancellation_cleanup_historic(
        cleanup,
        request,
        &value.cancellation,
        &prepared.source_device_ref,
        &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupHistoricTrustV1 {
            issuer: &cleanup.issuer,
            audience: &cleanup.audience,
            key_id: outer_key_id,
            public_key_hex: outer_public_key_hex,
            minimum_config_generation: outer_config_generation,
            cleanup_key_id: &value.cancellation_key_id,
            cleanup_public_key_hex: &value.cancellation_public_key_hex,
            minimum_cleanup_config_generation: value.cancellation_config_generation,
            minimum_snapshot_revision: cleanup.snapshot_revision,
            accepted_at_epoch_s: accepted,
        },
    )
    .is_ok()
}
