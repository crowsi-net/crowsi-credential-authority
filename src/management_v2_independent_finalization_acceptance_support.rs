fn reservation_valid(value: &Acceptance) -> bool {
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
        && request.pre_final_acceptance_request_sha256 == value.pre_final_request_sha256
        && request.reconcile_digest == value.reconcile_digest
        && request.original_request == value.pre_final_request.approve_revocation_request
        && request.prepared == value.pre_final_request.prepared
        && request.accepted_identity_exchange == value.accepted_identity_exchange
        && request.begin_exchange == value.begin_exchange
        && request.approval_exchange.as_ref() == Some(&value.approval_exchange)
        && historic_reservation(value, stored)
}

fn historic_reservation(
    value: &Acceptance,
    stored: &crate::management_v2_record::RevocationExecutionReservationAcceptanceV1,
) -> bool {
    let reservation = stored.reservation.as_ref();
    crowsi_credential_authority_contracts::verify_endpoint_revocation_execution_reservation_historic(
        reservation,
        &stored.reservation_request,
        identity_device(&value.accepted_identity_exchange).unwrap_or_default(),
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
}

fn final_valid(value: &Acceptance) -> bool {
    match (
        &value.execution_reservation,
        &value.finalize_request_sha256,
        &value.finalize_request,
        &value.final_revoke_exchange,
    ) {
        (None | Some(_), None, None, None) => true,
        (Some(stored), Some(digest), Some(request), Some(exchange)) => {
            lower_hex(digest, 64)
                && request.as_ref().final_revoke_exchange == *exchange
                && crowsi_credential_authority_contracts::endpoint_independent_revocation_finalize_request_digest(request)
                    .is_ok_and(|item| item == *digest)
                && crowsi_credential_authority_contracts::validate_endpoint_independent_revocation_finalize_against_acceptance(
                    request,
                    &value.pre_final_request,
                    &stored.reservation_request,
                    &stored.reservation,
                )
                .is_ok()
                && exchange.response.issued_at_epoch_s >= stored.accepted_at_epoch_s
        }
        _ => false,
    }
}

fn state_valid(state: State, value: &Acceptance) -> bool {
    match (
        &value.execution_reservation,
        &value.finalize_request_sha256,
        &value.finalize_request,
        &value.final_revoke_exchange,
    ) {
        (None, None, None, None) => {
            matches!(state, State::AwaitingRevocationFinal | State::Cancelled)
        }
        (Some(_), None, None, None) => state == State::RevocationExecutionReserved,
        (Some(_), Some(_), Some(_), Some(_)) => {
            matches!(state, State::Unknown | State::Completed)
        }
        _ => false,
    }
}

fn identity_device(
    value: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> Option<&str> {
    crowsi_credential_authority_contracts::identity_evidence_from_exchange(value)
        .ok()
        .map(|identity| identity.assertion.device_id.as_str())
}

fn self_revocation(
    value: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
) -> bool {
    value
        .revocation
        .as_ref()
        .is_some_and(|item| item.target_device_ref == value.source_device_ref)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}
