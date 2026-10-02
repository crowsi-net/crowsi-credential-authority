use crowsi_credential_authority_contracts::ManagementOperationState as State;

use crate::management_v2_record::{
    IndependentRevocationFinalizationAcceptanceV1 as Acceptance, ManagementRecordV2,
    ManagementTombstoneV2,
};

pub(crate) fn record(value: &ManagementRecordV2) -> bool {
    let Some(acceptance) = &value.independent_revocation_finalization else {
        return true;
    };
    !self_revocation(&value.prepared)
        && value.independent_identity_exchange.as_ref()
            == Some(&acceptance.accepted_identity_exchange)
        && value.independent_finish_uv_exchange.as_ref() == Some(&acceptance.finish_uv_exchange)
        && acceptance_valid(
            acceptance,
            value.authority_config_generation,
            &value.prepared,
            &value.operation,
        )
        && state_valid(value.operation.state, acceptance)
}

pub(crate) fn tombstone(value: &ManagementTombstoneV2) -> bool {
    value
        .independent_revocation_finalization
        .as_ref()
        .is_none_or(|acceptance| {
            !self_revocation(&value.prepared)
                && acceptance_valid(
                    acceptance,
                    value.authority_config_generation,
                    &value.prepared,
                    &value.operation,
                )
                && matches!(value.operation.state, State::Completed | State::Cancelled)
                && state_valid(value.operation.state, acceptance)
        })
}

pub(crate) fn pre_final_exact(
    value: &ManagementRecordV2,
    request: &crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1,
    peer: &str,
) -> bool {
    let Some(acceptance) = &value.independent_revocation_finalization else {
        return false;
    };
    value.operation.state == State::AwaitingRevocationFinal
        && value.operation.state_revision == acceptance.pre_final_state_revision
        && value.operation.reconcile_digest.as_deref() == Some(&acceptance.reconcile_digest)
        && value.owner_ref == request.prepared.opaque_owner_ref
        && value.prepared == request.prepared
        && acceptance.pre_final_request.as_ref() == request
        && acceptance.accepted_identity_exchange == request.accepted_identity_exchange
        && identity_device(&acceptance.accepted_identity_exchange) == Some(peer)
        && acceptance.execution_reservation.is_none()
        && acceptance.finalize_request_sha256.is_none()
        && acceptance.finalize_request.is_none()
        && acceptance.final_revoke_exchange.is_none()
}

fn acceptance_valid(
    acceptance: &Acceptance,
    generation: u64,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    operation: &crowsi_credential_authority_contracts::ManagementOperationV2,
) -> bool {
    let Ok(digest) = crowsi_credential_authority_contracts::endpoint_independent_revocation_pre_final_request_digest(
        &acceptance.pre_final_request,
    ) else {
        return false;
    };
    let request = &acceptance.pre_final_request;
    acceptance.accepted_at_epoch_s > 0
        && acceptance.pre_final_state_revision > 0
        && acceptance.pre_final_snapshot_revision > 0
        && acceptance.pre_final_request_sha256 == digest
        && lower_hex(&acceptance.reconcile_digest, 64)
        && request.accepted_identity_exchange == acceptance.accepted_identity_exchange
        && request.selected_identity_exchange == acceptance.selected_identity_exchange
        && request.begin_uv_exchange == acceptance.begin_uv_exchange
        && request.finish_uv_exchange == acceptance.finish_uv_exchange
        && request.revocation_ceremony.begin == acceptance.begin_exchange
        && request.revocation_ceremony.approval == acceptance.approval_exchange
        && acceptance.response_key_id == acceptance.begin_exchange.response.key_id
        && lower_hex(&acceptance.response_public_key_hex, 64)
        && acceptance.minimum_config_generation > 0
        && acceptance.minimum_config_generation <= generation
        && reservation_valid(acceptance)
        && final_valid(acceptance)
        && crate::management_v2_execution_cancellation_acceptance::independent_valid(
            acceptance, prepared, operation,
        )
}

include!("management_v2_independent_finalization_acceptance_support.rs");
