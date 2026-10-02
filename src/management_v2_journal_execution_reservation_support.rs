fn stored(
    config: &VerifiedHostConfig,
    request: &EndpointRevocationExecutionReserveRequestV1,
    reservation: &EndpointRevocationExecutionReservationV1,
    now: u64,
) -> Result<RevocationExecutionReservationAcceptanceV1, HostError> {
    Ok(RevocationExecutionReservationAcceptanceV1 {
        accepted_at_epoch_s: now,
        outer_key_id: config.document.management_projection_key_id.clone(),
        outer_public_key_hex: config.document.management_projection_public_key_hex.clone(),
        outer_config_generation: reservation.config_generation,
        reservation_key_id: config
            .document
            .revocation_execution_reservation_key_id
            .clone(),
        reservation_public_key_hex: config
            .document
            .revocation_execution_reservation_public_key_hex
            .clone(),
        reservation_config_generation: config
            .document
            .revocation_execution_reservation_config_generation,
        reservation_request_sha256: crowsi_credential_authority_contracts::endpoint_revocation_execution_reserve_request_digest(request)
            .map_err(|_| HostError::RequestInvalid)?,
        reservation_request: Box::new(request.clone()),
        reservation: Box::new(reservation.clone()),
    })
}

fn pre_final_exact(
    record: &crate::management_v2_record::ManagementRecordV2,
    request: &EndpointRevocationExecutionReserveRequestV1,
    peer: &str,
) -> Result<(), HostError> {
    let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(
        &request.accepted_identity_exchange,
    )
    .map_err(|_| HostError::EvidenceInvalid)?;
    let base = record.owner_ref == request.prepared.opaque_owner_ref
        && record.prepared == request.prepared
        && record.operation.operation_id == request.operation_id
        && record.operation.state == ManagementOperationState::AwaitingRevocationFinal
        && record.operation.state_revision == request.expected_state_revision
        && record.operation.reconcile_digest.as_deref() == Some(&request.reconcile_digest)
        && identity.assertion.device_id == peer;
    let accepted = match &request.original_request.command {
        crowsi_credential_authority_contracts::ManagementCommandV2::SourceApprove { .. } => {
            self_pre_final(record, request, peer)
        }
        crowsi_credential_authority_contracts::ManagementCommandV2::ApproveRevocation {
            ..
        } => independent_pre_final(record, request, peer),
        _ => false,
    };
    (base && accepted)
        .then_some(())
        .ok_or(HostError::StateInvalid)
}

fn self_pre_final(
    record: &crate::management_v2_record::ManagementRecordV2,
    request: &EndpointRevocationExecutionReserveRequestV1,
    peer: &str,
) -> bool {
    let Some(value) = &record.revocation_finalization else {
        return false;
    };
    peer == record.prepared.source_device_ref
        && value.source_approve_request == request.original_request
        && value.source_approve_request_sha256 == request.pre_final_acceptance_request_sha256
        && value.accepted_identity_exchange == request.accepted_identity_exchange
        && value.begin_exchange == request.begin_exchange
        && request.approval_exchange.is_none()
        && value.execution_reservation.is_none()
}

fn independent_pre_final(
    record: &crate::management_v2_record::ManagementRecordV2,
    request: &EndpointRevocationExecutionReserveRequestV1,
    peer: &str,
) -> bool {
    let Some(value) = &record.independent_revocation_finalization else {
        return false;
    };
    identity_device(&value.accepted_identity_exchange) == Some(peer)
        && value.pre_final_request.approve_revocation_request == request.original_request
        && value.pre_final_request_sha256 == request.pre_final_acceptance_request_sha256
        && value.accepted_identity_exchange == request.accepted_identity_exchange
        && value.begin_exchange == request.begin_exchange
        && request.approval_exchange.as_ref() == Some(&value.approval_exchange)
        && value.execution_reservation.is_none()
}

include!("management_v2_journal_execution_reservation_view.rs");
