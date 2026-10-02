fn exact_base(
    value: &ManagementRecordV2,
    request: &EndpointRevocationFinalizeRequestV1,
    peer: &str,
) -> Result<(), HostError> {
    let acceptance = value
        .revocation_finalization
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let exact = value.owner_ref == request.prepared.opaque_owner_ref
        && value.prepared == request.prepared
        && value.prepared.source_device_ref == peer
        && acceptance.accepted_identity_exchange == request.accepted_identity_exchange
        && acceptance.reconcile_digest == request.reconcile_digest
        && acceptance.source_approve_request == request.source_approve_request;
    exact.then_some(()).ok_or(HostError::EvidenceInvalid)
}

fn verify_new(
    acceptance: &crate::management_v2_record::RevocationFinalizationAcceptanceV1,
    request: &EndpointRevocationFinalizeRequestV1,
) -> Result<(), HostError> {
    let reservation = acceptance
        .execution_reservation
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    crowsi_credential_authority_contracts::validate_endpoint_revocation_finalize_against_acceptance(
        request,
        &acceptance.source_approve_request_sha256,
        &acceptance.begin_exchange,
        &reservation.reservation_request,
        &reservation.reservation,
    )
    .map_err(|_| HostError::EvidenceInvalid)?;
    if request.final_revoke_exchange.response.issued_at_epoch_s < reservation.accepted_at_epoch_s {
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

fn exact_record(
    value: &ManagementRecordV2,
    request: &EndpointRevocationFinalizeRequestV1,
    peer: &str,
) -> Result<(), HostError> {
    exact_base(value, request, peer)?;
    let acceptance = value
        .revocation_finalization
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    (acceptance.finalize_request_sha256.as_deref() == Some(&request_digest(request)?)
        && acceptance.finalize_request.as_deref() == Some(request)
        && acceptance.final_revoke_exchange.as_ref() == Some(&request.final_revoke_exchange)
        && matches!(
            value.operation.state,
            ManagementOperationState::Unknown | ManagementOperationState::Completed
        ))
    .then_some(())
    .ok_or(HostError::StateInvalid)
}

fn exact_tombstone(
    value: &ManagementTombstoneV2,
    request: &EndpointRevocationFinalizeRequestV1,
    peer: &str,
) -> Result<(), HostError> {
    let acceptance = value
        .revocation_finalization
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let exact = value.owner_ref == request.prepared.opaque_owner_ref
        && value.prepared == request.prepared
        && value.prepared.source_device_ref == peer
        && value.operation.state == ManagementOperationState::Completed
        && acceptance.accepted_identity_exchange == request.accepted_identity_exchange
        && acceptance.reconcile_digest == request.reconcile_digest
        && acceptance.finalize_request_sha256.as_deref() == Some(&request_digest(request)?)
        && acceptance.finalize_request.as_deref() == Some(request)
        && acceptance.final_revoke_exchange.as_ref() == Some(&request.final_revoke_exchange);
    exact.then_some(()).ok_or(HostError::StateInvalid)
}

fn request_digest(value: &EndpointRevocationFinalizeRequestV1) -> Result<String, HostError> {
    crowsi_credential_authority_contracts::endpoint_revocation_finalize_request_digest(value)
        .map_err(|_| HostError::RequestInvalid)
}
