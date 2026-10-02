#[allow(clippy::too_many_arguments)]
fn store_acceptance(
    slot: &mut bool,
    cleanup_completed: bool,
    delivery_completed: &mut bool,
    value: Option<&mut crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1>,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    complete: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
    config: &VerifiedHostConfig,
    now: u64,
) -> Result<(), HostError> {
    let value = value.ok_or(HostError::StateInvalid)?;
    if !*slot || !cleanup_completed || *delivery_completed || value.cleanup_delivery.is_some() {
        return Err(HostError::StateInvalid);
    }
    value.cleanup_delivery_accepted_at_epoch_s = Some(now);
    value.cleanup_delivery_outer_key_id =
        Some(config.document.management_projection_key_id.clone());
    value.cleanup_delivery_outer_public_key_hex =
        Some(config.document.management_projection_public_key_hex.clone());
    value.cleanup_delivery_outer_config_generation = Some(complete.config_generation);
    value.cleanup_delivery_acknowledge_key_id =
        Some(config.document.identity_response_key_id.clone());
    value.cleanup_delivery_acknowledge_public_key_hex =
        Some(config.document.identity_response_public_key_hex.clone());
    value.cleanup_delivery_acknowledge_minimum_config_generation =
        Some(config.document.minimum_identity_config_generation);
    value.cleanup_delivery_request_sha256 = Some(
        crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_cleanup_complete_request_digest(request)
            .map_err(|_| HostError::RequestInvalid)?,
    );
    value.cleanup_delivery_request = Some(Box::new(request.clone()));
    value.cleanup_delivery = Some(Box::new(complete.clone()));
    *slot = false;
    *delivery_completed = true;
    Ok(())
}
