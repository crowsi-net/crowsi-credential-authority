fn accept(
    value: &mut ManagementRecordV2,
    request: &EndpointIndependentRevocationFinalizeRequestV1,
    peer: &str,
    generation_head: u64,
) -> Result<bool, HostError> {
    exact_base(value, request, peer)?;
    let acceptance = value
        .independent_revocation_finalization
        .as_mut()
        .ok_or(HostError::StateInvalid)?;
    let digest = request_digest(request)?;
    if let (Some(stored), Some(stored_value), Some(final_exchange)) = (
        &acceptance.finalize_request_sha256,
        &acceptance.finalize_request,
        &acceptance.final_revoke_exchange,
    ) {
        return (stored == &digest
            && stored_value.as_ref() == request
            && final_exchange == &request.final_revoke_exchange
            && matches!(
                value.operation.state,
                ManagementOperationState::Unknown | ManagementOperationState::Completed
            ))
        .then_some(false)
        .ok_or(HostError::StateInvalid);
    }
    if value.operation.state != ManagementOperationState::RevocationExecutionReserved
        || value.operation.state_revision != request.expected_state_revision
        || value.operation.reconcile_digest.as_deref() != Some(&request.reconcile_digest)
    {
        return Err(HostError::StateInvalid);
    }
    verify_new(acceptance, request)?;
    acceptance.finalize_request_sha256 = Some(digest);
    acceptance.finalize_request = Some(Box::new(request.clone()));
    acceptance.final_revoke_exchange = Some(request.final_revoke_exchange.clone());
    value.authority_config_generation = value
        .authority_config_generation
        .max(request.final_revoke_exchange.response.config_generation)
        .max(generation_head);
    value.operation.state_revision =
        crate::management_v2_journal_policy::next(value.operation.state_revision)?;
    value.operation.state = ManagementOperationState::Unknown;
    value.operation.reason = Some(ManagementReasonCode::ProviderOutcomeUnknown);
    value.operation.actor = crate::management_v2_state::reconcile_actor();
    value.operation.webauthn_options = None;
    Ok(true)
}

fn verify_new(
    acceptance: &crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
    request: &EndpointIndependentRevocationFinalizeRequestV1,
) -> Result<(), HostError> {
    let stored = acceptance
        .execution_reservation
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    crowsi_credential_authority_contracts::validate_endpoint_independent_revocation_finalize_against_acceptance(
        request,
        &acceptance.pre_final_request,
        &stored.reservation_request,
        &stored.reservation,
    )
    .map_err(|_| HostError::EvidenceInvalid)?;
    if request.final_revoke_exchange.response.issued_at_epoch_s < stored.accepted_at_epoch_s {
        return Err(HostError::EvidenceInvalid);
    }
    let command =
        crate::management_v2_revocation_finalization::command(&request.final_revoke_exchange)?;
    crowsi_credential_authority_contracts::verify_authority_exchange_historic(
        &request.final_revoke_exchange,
        command,
        acceptance.minimum_config_generation,
        &acceptance.response_key_id,
        &acceptance.response_public_key_hex,
    )
    .map_err(|_| HostError::EvidenceInvalid)
}

include!("management_v2_journal_independent_finalization_validation.rs");
