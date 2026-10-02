use crowsi_credential_authority_contracts::{ManagementOperationState, ManagementReasonCode};

use crate::{HostError, management_v2_record::ManagementRecordV2};

pub(crate) fn bump(value: &mut ManagementRecordV2) -> Result<(), HostError> {
    value.operation.state_revision = value
        .operation
        .state_revision
        .checked_add(1)
        .ok_or(HostError::StateInvalid)?;
    Ok(())
}

pub(crate) fn complete(value: &mut ManagementRecordV2) -> Result<(), HostError> {
    value.operation.state = ManagementOperationState::Completed;
    bump(value)?;
    value.operation.reason = None;
    value.operation.reconcile_digest = None;
    value.operation.actor = crate::management_v2_state::none_actor();
    Ok(())
}

pub(crate) fn terminal(
    value: &mut ManagementRecordV2,
    state: ManagementOperationState,
    reason: Option<ManagementReasonCode>,
) -> Result<(), HostError> {
    value.operation.state = state;
    bump(value)?;
    value.operation.reason = reason;
    value.operation.reconcile_digest = None;
    value.operation.actor = crate::management_v2_state::none_actor();
    Ok(())
}

pub(crate) fn arm(value: &mut ManagementRecordV2) -> Result<(), HostError> {
    value.operation.state = ManagementOperationState::Unknown;
    value.operation.reason = Some(ManagementReasonCode::ProviderOutcomeUnknown);
    let wire = serde_json::to_vec(&(
        "CROWSI-MANAGEMENT-RECONCILE-V2",
        &value.operation.operation_id,
        &value.prepared,
    ))
    .map_err(|_| HostError::StateInvalid)?;
    value.operation.reconcile_digest = Some(
        crate::host_crypto::digest(&wire)
            .trim_start_matches("sha256:")
            .to_owned(),
    );
    value.operation.actor = crate::management_v2_state::reconcile_actor();
    Ok(())
}
