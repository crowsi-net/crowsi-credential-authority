fn exact_base(
    value: &ManagementRecordV2,
    request: &EndpointIndependentRevocationFinalizeRequestV1,
    peer: &str,
) -> Result<(), HostError> {
    let acceptance = value
        .independent_revocation_finalization
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let reservation = acceptance
        .execution_reservation
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let exact = value.owner_ref == request.prepared.opaque_owner_ref
        && value.prepared == request.prepared
        && reservation.reservation.finalizer_device_ref == peer
        && acceptance.accepted_identity_exchange == request.accepted_identity_exchange
        && acceptance.pre_final_request_sha256 == request.pre_final_request_sha256
        && acceptance.reconcile_digest == request.reconcile_digest
        && acceptance.pre_final_request.approve_revocation_request
            == request.approve_revocation_request;
    exact.then_some(()).ok_or(HostError::EvidenceInvalid)
}

fn exact_record(
    value: &ManagementRecordV2,
    request: &EndpointIndependentRevocationFinalizeRequestV1,
    peer: &str,
) -> Result<(), HostError> {
    exact_base(value, request, peer)?;
    let acceptance = value
        .independent_revocation_finalization
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
    request: &EndpointIndependentRevocationFinalizeRequestV1,
    peer: &str,
) -> Result<(), HostError> {
    let acceptance = value
        .independent_revocation_finalization
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let reservation = acceptance
        .execution_reservation
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let exact = value.owner_ref == request.prepared.opaque_owner_ref
        && value.prepared == request.prepared
        && value.operation.state == ManagementOperationState::Completed
        && reservation.reservation.finalizer_device_ref == peer
        && acceptance.accepted_identity_exchange == request.accepted_identity_exchange
        && acceptance.reconcile_digest == request.reconcile_digest
        && acceptance.finalize_request_sha256.as_deref() == Some(&request_digest(request)?)
        && acceptance.finalize_request.as_deref() == Some(request)
        && acceptance.final_revoke_exchange.as_ref() == Some(&request.final_revoke_exchange);
    exact.then_some(()).ok_or(HostError::StateInvalid)
}

fn request_digest(
    value: &EndpointIndependentRevocationFinalizeRequestV1,
) -> Result<String, HostError> {
    crowsi_credential_authority_contracts::endpoint_independent_revocation_finalize_request_digest(
        value,
    )
    .map_err(|_| HostError::RequestInvalid)
}
