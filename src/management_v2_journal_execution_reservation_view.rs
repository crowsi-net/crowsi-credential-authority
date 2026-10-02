fn store(
    record: &mut crate::management_v2_record::ManagementRecordV2,
    request: &EndpointRevocationExecutionReserveRequestV1,
    value: RevocationExecutionReservationAcceptanceV1,
) -> Result<(), HostError> {
    match &request.original_request.command {
        crowsi_credential_authority_contracts::ManagementCommandV2::SourceApprove { .. } => {
            record
                .revocation_finalization
                .as_mut()
                .ok_or(HostError::StateInvalid)?
                .execution_reservation = Some(value);
        }
        crowsi_credential_authority_contracts::ManagementCommandV2::ApproveRevocation {
            ..
        } => {
            record
                .independent_revocation_finalization
                .as_mut()
                .ok_or(HostError::StateInvalid)?
                .execution_reservation = Some(value);
        }
        _ => return Err(HostError::RequestInvalid),
    }
    Ok(())
}

fn reservation_from_record(
    value: &crate::management_v2_record::ManagementRecordV2,
    request: &EndpointRevocationExecutionReserveRequestV1,
    peer: &str,
) -> Option<EndpointRevocationExecutionReservationV1> {
    reservation(
        value.operation.operation_id.as_str(),
        value
            .revocation_finalization
            .as_ref()
            .and_then(|item| item.execution_reservation.as_ref()),
        value
            .independent_revocation_finalization
            .as_ref()
            .and_then(|item| item.execution_reservation.as_ref()),
        request,
        peer,
    )
}

fn reservation_from_tombstone(
    value: &crate::management_v2_record::ManagementTombstoneV2,
    request: &EndpointRevocationExecutionReserveRequestV1,
    peer: &str,
) -> Option<EndpointRevocationExecutionReservationV1> {
    reservation(
        value.operation.operation_id.as_str(),
        value
            .revocation_finalization
            .as_ref()
            .and_then(|item| item.execution_reservation.as_ref()),
        value
            .independent_revocation_finalization
            .as_ref()
            .and_then(|item| item.execution_reservation.as_ref()),
        request,
        peer,
    )
}

fn reservation(
    operation_id: &str,
    self_value: Option<&RevocationExecutionReservationAcceptanceV1>,
    independent: Option<&RevocationExecutionReservationAcceptanceV1>,
    request: &EndpointRevocationExecutionReserveRequestV1,
    peer: &str,
) -> Option<EndpointRevocationExecutionReservationV1> {
    let stored = match &request.original_request.command {
        crowsi_credential_authority_contracts::ManagementCommandV2::SourceApprove { .. } => {
            self_value
        }
        crowsi_credential_authority_contracts::ManagementCommandV2::ApproveRevocation {
            ..
        } => independent,
        _ => None,
    }?;
    let exact = operation_id == request.operation_id
        && stored.reservation_request.as_ref() == request
        && stored.reservation.finalizer_device_ref == peer
        && stored.reservation_request_sha256
            == crowsi_credential_authority_contracts::endpoint_revocation_execution_reserve_request_digest(request).ok()?;
    exact.then(|| stored.reservation.as_ref().clone())
}

fn identity_device(
    value: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> Option<&str> {
    crowsi_credential_authority_contracts::identity_evidence_from_exchange(value)
        .ok()
        .map(|identity| identity.assertion.device_id.as_str())
}
