fn delivery_phase(
    value: &crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
    completed: bool,
    prepared: &EndpointPreparedOperationV2,
) -> bool {
    match (
        value.cleanup_delivery_accepted_at_epoch_s,
        &value.cleanup_delivery_outer_key_id,
        &value.cleanup_delivery_outer_public_key_hex,
        value.cleanup_delivery_outer_config_generation,
        &value.cleanup_delivery_acknowledge_key_id,
        &value.cleanup_delivery_acknowledge_public_key_hex,
        value.cleanup_delivery_acknowledge_minimum_config_generation,
        &value.cleanup_delivery_request_sha256,
        &value.cleanup_delivery_request,
        &value.cleanup_delivery,
    ) {
        (None, None, None, None, None, None, None, None, None, None) => !completed,
        (
            Some(accepted),
            Some(outer_key),
            Some(outer_public),
            Some(outer_generation),
            Some(acknowledge_key),
            Some(acknowledge_public),
            Some(acknowledge_generation),
            Some(digest),
            Some(request),
            Some(delivery),
        ) => {
            completed
                && value.cleanup_accepted_at_epoch_s.is_some_and(|item| accepted >= item)
                && crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_cleanup_complete_request_digest(request)
                    .is_ok_and(|item| item == *digest)
                && crowsi_credential_authority_contracts::verify_endpoint_revocation_execution_cancellation_cleanup_complete_historic(
                    delivery,
                    request,
                    &request.cleanup,
                    &prepared.source_device_ref,
                    &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupCompleteHistoricTrustV1 {
                        issuer: &delivery.issuer,
                        audience: &delivery.audience,
                        key_id: outer_key,
                        public_key_hex: outer_public,
                        minimum_config_generation: outer_generation,
                        cleanup_key_id: &value.cancellation_key_id,
                        cleanup_public_key_hex: &value.cancellation_public_key_hex,
                        minimum_cleanup_config_generation: value.cancellation_config_generation,
                        acknowledge_key_id: acknowledge_key,
                        acknowledge_public_key_hex: acknowledge_public,
                        minimum_acknowledge_config_generation: acknowledge_generation,
                        minimum_snapshot_revision: delivery.snapshot_revision,
                        accepted_at_epoch_s: accepted,
                    },
                )
                .is_ok()
        }
        _ => false,
    }
}
