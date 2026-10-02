use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementOperationState, ManagementOperationV2,
};

use crate::management_v2_record::{
    IndependentRevocationFinalizationAcceptanceV1, RevocationFinalizationAcceptanceV1,
};

pub(crate) fn self_valid(
    value: &RevocationFinalizationAcceptanceV1,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
) -> bool {
    valid(
        value.accepted_at_epoch_s,
        &value.source_approve_request_sha256,
        &value.begin_exchange,
        &value.response_key_id,
        &value.response_public_key_hex,
        value.minimum_config_generation,
        cleanup_state(
            value.cancellation_slot_reserved,
            value.cancellation_cleanup_completed,
            value.cancellation_cleanup_delivery_completed,
        ),
        value.execution_reservation.is_some()
            || value.finalize_request.is_some()
            || value.final_revoke_exchange.is_some(),
        value.execution_cancellation.as_ref(),
        prepared,
        operation,
    )
}

pub(crate) fn independent_valid(
    value: &IndependentRevocationFinalizationAcceptanceV1,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
) -> bool {
    valid(
        value.accepted_at_epoch_s,
        &value.pre_final_request_sha256,
        &value.begin_exchange,
        &value.response_key_id,
        &value.response_public_key_hex,
        value.minimum_config_generation,
        cleanup_state(
            value.cancellation_slot_reserved,
            value.cancellation_cleanup_completed,
            value.cancellation_cleanup_delivery_completed,
        ),
        value.execution_reservation.is_some()
            || value.finalize_request.is_some()
            || value.final_revoke_exchange.is_some(),
        value.execution_cancellation.as_ref(),
        prepared,
        operation,
    )
}

#[allow(clippy::too_many_arguments)]
fn valid(
    pre_final_accepted_at: u64,
    pre_final_digest: &str,
    begin_exchange: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    response_key_id: &str,
    response_public_key_hex: &str,
    minimum_config_generation: u64,
    cleanup: Option<CleanupState>,
    final_side: bool,
    stored: Option<&crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1>,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
) -> bool {
    let Some(cleanup) = cleanup else {
        return false;
    };
    match stored {
        None => match cleanup {
            CleanupState::Absent => operation.state != ManagementOperationState::Cancelled,
            CleanupState::Reserved => {
                operation.state == ManagementOperationState::Cancelled && !final_side
            }
            CleanupState::Cleaned | CleanupState::Delivered => false,
        },
        Some(value) => {
            let (slot, completed, delivery_completed) = cleanup.flags();
            operation.state == ManagementOperationState::Cancelled
                && !final_side
                && cancellation(
                    value,
                    pre_final_accepted_at,
                    pre_final_digest,
                    begin_exchange,
                    response_key_id,
                    response_public_key_hex,
                    minimum_config_generation,
                    prepared,
                    operation,
                )
                && cleanup_phase(value, slot, completed, delivery_completed, prepared)
        }
    }
}

#[derive(Clone, Copy)]
enum CleanupState {
    Absent,
    Reserved,
    Cleaned,
    Delivered,
}

impl CleanupState {
    const fn flags(self) -> (bool, bool, bool) {
        match self {
            Self::Absent => (false, false, false),
            Self::Reserved => (true, false, false),
            Self::Cleaned => (true, true, false),
            Self::Delivered => (false, true, true),
        }
    }
}

fn cleanup_state(slot: bool, completed: bool, delivered: bool) -> Option<CleanupState> {
    match (slot, completed, delivered) {
        (false, false, false) => Some(CleanupState::Absent),
        (true, false, false) => Some(CleanupState::Reserved),
        (true, true, false) => Some(CleanupState::Cleaned),
        (false, true, true) => Some(CleanupState::Delivered),
        _ => None,
    }
}

include!("management_v2_execution_cancellation_acceptance_validation.rs");
include!("management_v2_execution_cancellation_acceptance_delivery.rs");
