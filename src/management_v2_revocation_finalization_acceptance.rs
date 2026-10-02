use crowsi_credential_authority_contracts::ManagementOperationState as State;

use crate::management_v2_record::{
    ManagementRecordV2, ManagementTombstoneV2, RevocationFinalizationAcceptanceV1 as Acceptance,
};

pub(crate) fn record(value: &ManagementRecordV2) -> bool {
    let Some(acceptance) = &value.revocation_finalization else {
        return !self_revocation(value) || value.source_revocation_ceremony.is_none();
    };
    self_revocation(value)
        && value
            .source_approval_identity_exchange
            .as_ref()
            .is_some_and(|item| item == &acceptance.accepted_identity_exchange)
        && value
            .source_revocation_ceremony
            .as_ref()
            .is_some_and(|item| {
                item.begin == acceptance.begin_exchange && item.final_revoke.is_none()
            })
        && value
            .source_approval_acceptance_sha256
            .as_deref()
            .and_then(|item| item.strip_prefix("sha256:"))
            == Some(&acceptance.source_approve_request_sha256)
        && valid(
            acceptance,
            value.authority_config_generation,
            &value.prepared,
            &value.operation,
        )
        && state(value.operation.state, acceptance)
}

pub(crate) fn tombstone(value: &ManagementTombstoneV2) -> bool {
    if self_revocation_tombstone(value) && value.revocation_finalization.is_none() {
        return matches!(
            value.operation.state,
            State::Rejected | State::Cancelled | State::Expired
        );
    }
    value.revocation_finalization.as_ref().is_none_or(|item| {
        ((value.operation.state == State::Completed
            && item.final_revoke_exchange.is_some()
            && item.finalize_request_sha256.is_some()
            && item.finalize_request.is_some())
            || (value.operation.state == State::Cancelled
                && item.final_revoke_exchange.is_none()
                && item.finalize_request_sha256.is_none()
                && item.finalize_request.is_none()))
            && valid(
                item,
                value.authority_config_generation,
                &value.prepared,
                &value.operation,
            )
    })
}

fn valid(
    value: &Acceptance,
    record_generation: u64,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    operation: &crowsi_credential_authority_contracts::ManagementOperationV2,
) -> bool {
    let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(
        &value.accepted_identity_exchange,
    );
    let begin = match &value.begin_exchange.request.command {
        ihat_identity_assertion_contracts::AuthorityCommand::BeginDeviceRevocation(_) => {
            "begin_device_revocation"
        }
        ihat_identity_assertion_contracts::AuthorityCommand::BeginSessionRevocation(_) => {
            "begin_session_revocation"
        }
        _ => return false,
    };
    let base = value.accepted_at_epoch_s > 0
        && value.pre_final_state_revision > 0
        && value.pre_final_snapshot_revision > 0
        && bare_digest(&value.source_approve_request_sha256)
        && bare_digest(&value.reconcile_digest)
        && source_request(value, prepared)
        && identity.is_ok()
        && value.response_key_id == value.begin_exchange.response.key_id
        && id(&value.response_key_id)
        && lower_hex(&value.response_public_key_hex, 64)
        && value.minimum_config_generation > 0
        && value.minimum_config_generation >= value.begin_exchange.response.config_generation
        && value.minimum_config_generation
            >= value.accepted_identity_exchange.response.config_generation
        && value.minimum_config_generation <= record_generation
        && crowsi_credential_authority_contracts::validate_authority_exchange(
            &value.begin_exchange,
            begin,
        )
        .is_ok()
        && crowsi_credential_authority_contracts::verify_authority_exchange_historic(
            &value.begin_exchange,
            begin,
            value.begin_exchange.response.config_generation,
            &value.response_key_id,
            &value.response_public_key_hex,
        )
        .is_ok()
        && crowsi_credential_authority_contracts::verify_authority_exchange_historic(
            &value.accepted_identity_exchange,
            "issue_current_device_identity_evidence",
            value.accepted_identity_exchange.response.config_generation,
            &value.response_key_id,
            &value.response_public_key_hex,
        )
        .is_ok()
        && self_reservation_valid(value, prepared)
        && crate::management_v2_execution_cancellation_acceptance::self_valid(
            value, prepared, operation,
        );
    match (
        &value.execution_reservation,
        &value.finalize_request_sha256,
        &value.finalize_request,
        &value.final_revoke_exchange,
    ) {
        (None | Some(_), None, None, None) => base,
        (Some(reservation), Some(digest), Some(request), Some(final_exchange)) => {
            base && bare_digest(digest)
                && request.as_ref().final_revoke_exchange == *final_exchange
                && crowsi_credential_authority_contracts::endpoint_revocation_finalize_request_digest(request)
                    .is_ok_and(|item| item == *digest)
                && final_exchange.response.issued_at_epoch_s >= value.accepted_at_epoch_s
                && crowsi_credential_authority_contracts::validate_endpoint_revocation_finalize_against_acceptance(
                    request,
                    &value.source_approve_request_sha256,
                    &value.begin_exchange,
                    &reservation.reservation_request,
                    &reservation.reservation,
                )
                .is_ok()
                && historic(value, final_exchange)
        }
        _ => false,
    }
}

include!("management_v2_revocation_finalization_acceptance_support.rs");
