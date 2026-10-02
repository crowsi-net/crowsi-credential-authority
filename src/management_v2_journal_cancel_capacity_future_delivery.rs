fn complete_delivery(
    value: Option<&crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1>,
    _prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
    config: &VerifiedHostConfig,
) -> Result<crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1, HostError> {
    let mut result = value.cloned().ok_or(HostError::StateInvalid)?;
    let finalize_request = result
        .cleanup_request
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let cleanup = result.cleanup.as_ref().ok_or(HostError::StateInvalid)?;
    let acknowledgement = maximum_acknowledgement_exchange(cleanup)?;
    let request = EndpointRevocationExecutionCancelCleanupCompleteRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCEL_CLEANUP_COMPLETE_REQUEST_SCHEMA.into(),
        request_id: maximum_id(5),
        operation_id: operation.operation_id.clone(),
        cancel_finalize_request: Box::new(finalize_request.as_ref().clone()),
        cleanup: Box::new(cleanup.as_ref().clone()),
        acknowledge_exchange: acknowledgement,
    };
    let max = maximum_config(config);
    let complete = crate::management_v2_execution_cancellation_cleanup_complete_build::build(
        &max,
        &request,
        operation.clone(),
        u64::MAX,
        CAPACITY_TIME,
    )?;
    set_delivery(&mut result, request, complete, &max)?;
    Ok(result)
}

fn cancellation_acceptance(
    config: &VerifiedHostConfig,
    request: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelRequestV1,
    cancellation: crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationV1,
) -> crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1 {
    crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1 {
        accepted_at_epoch_s: CAPACITY_TIME,
        outer_key_id: config.document.management_projection_key_id.clone(),
        outer_public_key_hex: config.document.management_projection_public_key_hex.clone(),
        outer_config_generation: u64::MAX,
        cancellation_key_id: config
            .document
            .revocation_execution_reservation_key_id
            .clone(),
        cancellation_public_key_hex: config
            .document
            .revocation_execution_reservation_public_key_hex
            .clone(),
        cancellation_config_generation: u64::MAX,
        cancellation_request_sha256: cancellation.cancellation_request_sha256.clone(),
        cancellation_request: Box::new(request.clone()),
        cancellation: Box::new(cancellation),
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
    }
}

fn set_cleanup(
    value: &mut crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
    request: EndpointRevocationExecutionCancelFinalizeRequestV1,
    cleanup: crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupV1,
    exchange: SignedAuthorityExchangeV1,
    config: &VerifiedHostConfig,
) {
    value.cleanup_exchange = Some(exchange);
    value.cleanup_accepted_at_epoch_s = Some(CAPACITY_TIME);
    value.cleanup_outer_key_id = Some(config.document.management_projection_key_id.clone());
    value.cleanup_outer_public_key_hex =
        Some(config.document.management_projection_public_key_hex.clone());
    value.cleanup_outer_config_generation = Some(u64::MAX);
    value.cleanup_request_sha256 = Some(cleanup.cancel_finalize_request_sha256.clone());
    value.cleanup_request = Some(Box::new(request));
    value.cleanup = Some(Box::new(cleanup));
}

fn set_delivery(
    value: &mut crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1,
    request: EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    complete: crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupCompleteV1,
    config: &VerifiedHostConfig,
) -> Result<(), HostError> {
    value.cleanup_delivery_accepted_at_epoch_s = Some(CAPACITY_TIME);
    value.cleanup_delivery_outer_key_id =
        Some(config.document.management_projection_key_id.clone());
    value.cleanup_delivery_outer_public_key_hex =
        Some(config.document.management_projection_public_key_hex.clone());
    value.cleanup_delivery_outer_config_generation = Some(u64::MAX);
    value.cleanup_delivery_acknowledge_key_id =
        Some(config.document.identity_response_key_id.clone());
    value.cleanup_delivery_acknowledge_public_key_hex =
        Some(config.document.identity_response_public_key_hex.clone());
    value.cleanup_delivery_acknowledge_minimum_config_generation = Some(u64::MAX);
    value.cleanup_delivery_request_sha256 = Some(
        crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_cleanup_complete_request_digest(&request)
            .map_err(|_| HostError::RequestInvalid)?,
    );
    value.cleanup_delivery_request = Some(Box::new(request));
    value.cleanup_delivery = Some(Box::new(complete));
    Ok(())
}
