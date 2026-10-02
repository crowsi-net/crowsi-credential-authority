use crowsi_credential_authority_contracts::ManagementOperationState;

use crate::{HostError, management_v2_record::ManagementRecordV2};

pub(crate) fn completed(value: &mut ManagementRecordV2) -> Result<(), HostError> {
    value.operation.state = ManagementOperationState::Completed;
    value.operation.state_revision = next(value.operation.state_revision)?;
    value.operation.reason = None;
    value.operation.reconcile_digest = None;
    value.operation.actor = crate::management_v2_state::none_actor();
    Ok(())
}

pub(crate) fn preauthorized(value: &mut ManagementRecordV2) -> Result<(), HostError> {
    let acceptance = value
        .revocation_finalization
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    value.operation.state = ManagementOperationState::AwaitingRevocationFinal;
    value.operation.reason = None;
    value.operation.reconcile_digest = Some(acceptance.reconcile_digest.clone());
    value.operation.actor = crate::management_v2_state::reconcile_actor();
    Ok(())
}

fn next(value: u64) -> Result<u64, HostError> {
    value.checked_add(1).ok_or(HostError::StateInvalid)
}
