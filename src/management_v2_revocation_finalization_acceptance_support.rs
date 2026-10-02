fn self_revocation(value: &ManagementRecordV2) -> bool {
    value
        .prepared
        .revocation
        .as_ref()
        .is_some_and(|item| item.target_device_ref == value.prepared.source_device_ref)
}

fn self_revocation_tombstone(value: &ManagementTombstoneV2) -> bool {
    value
        .prepared
        .revocation
        .as_ref()
        .is_some_and(|item| item.target_device_ref == value.prepared.source_device_ref)
}

fn historic(
    value: &Acceptance,
    exchange: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> bool {
    let command = match &exchange.request.command {
        ihat_identity_assertion_contracts::AuthorityCommand::RevokeDeviceByRef(_) => {
            "revoke_device_by_ref"
        }
        ihat_identity_assertion_contracts::AuthorityCommand::RevokeSessionByRef(_) => {
            "revoke_session_by_ref"
        }
        _ => return false,
    };
    crowsi_credential_authority_contracts::verify_authority_exchange_historic(
        exchange,
        command,
        value.minimum_config_generation,
        &value.response_key_id,
        &value.response_public_key_hex,
    )
    .is_ok()
}

fn self_reservation_valid(
    value: &Acceptance,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
) -> bool {
    let Some(stored) = &value.execution_reservation else {
        return true;
    };
    let request = stored.reservation_request.as_ref();
    let reservation = stored.reservation.as_ref();
    let Ok(digest) =
        crowsi_credential_authority_contracts::endpoint_revocation_execution_reserve_request_digest(
            request,
        )
    else {
        return false;
    };
    stored.accepted_at_epoch_s >= value.accepted_at_epoch_s
        && stored.reservation_request_sha256 == digest
        && stored.outer_key_id == reservation.key_id
        && stored.outer_config_generation == reservation.config_generation
        && stored.reservation_key_id == reservation.token.key_id
        && stored.reservation_config_generation == reservation.reservation_config_generation
        && lower_hex(&stored.outer_public_key_hex, 64)
        && lower_hex(&stored.reservation_public_key_hex, 64)
        && request.pre_final_acceptance_request_sha256 == value.source_approve_request_sha256
        && request.reconcile_digest == value.reconcile_digest
        && request.original_request == value.source_approve_request
        && request.prepared == *prepared
        && request.accepted_identity_exchange == value.accepted_identity_exchange
        && request.begin_exchange == value.begin_exchange
        && request.approval_exchange.is_none()
        && self_reservation_historic(value, stored)
}

fn self_reservation_historic(
    value: &Acceptance,
    stored: &crate::management_v2_record::RevocationExecutionReservationAcceptanceV1,
) -> bool {
    let reservation = stored.reservation.as_ref();
    crowsi_credential_authority_contracts::verify_endpoint_revocation_execution_reservation_historic(
        reservation,
        &stored.reservation_request,
        &stored.reservation_request.prepared.source_device_ref,
        &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationHistoricTrustV1 {
            issuer: &reservation.issuer,
            audience: &reservation.audience,
            key_id: &stored.outer_key_id,
            public_key_hex: &stored.outer_public_key_hex,
            minimum_config_generation: stored.outer_config_generation,
            reservation_key_id: &stored.reservation_key_id,
            reservation_public_key_hex: &stored.reservation_public_key_hex,
            minimum_reservation_config_generation: stored.reservation_config_generation,
            minimum_snapshot_revision: reservation.snapshot_revision,
            accepted_at_epoch_s: stored.accepted_at_epoch_s,
        },
    )
    .is_ok()
        && value.response_key_id == value.begin_exchange.response.key_id
}

fn source_request(
    value: &Acceptance,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
) -> bool {
    let Ok(wire) = serde_json::to_vec(&value.source_approve_request) else {
        return false;
    };
    if crowsi_credential_authority_contracts::decode_management_request_strict(&wire).is_err() {
        return false;
    }
    matches!(
        &value.source_approve_request.command,
        crowsi_credential_authority_contracts::ManagementCommandV2::SourceApprove {
            operation_id,
            expected_state_revision,
            ..
        } if operation_id == &prepared.operation_id
            && expected_state_revision.checked_add(1)
                == Some(value.pre_final_state_revision)
    )
}

include!("management_v2_revocation_finalization_acceptance_state.rs");
