use crowsi_credential_authority_contracts::{
    ActorRequirementV2, EndpointPreparedOperationV2, ManagementIntentV2, ManagementOperationState,
    RequiredActorRole,
};

use crate::{HostError, management_v2_record::ManagementRecordV2};

pub(crate) fn source(value: &mut ManagementRecordV2) -> Result<(), HostError> {
    if value
        .prepared
        .revocation
        .as_ref()
        .is_some_and(|requirements| {
            requirements.target_device_ref == value.prepared.source_device_ref
        })
    {
        value.operation.state_revision = next(value.operation.state_revision)?;
        value.operation.webauthn_options = None;
        return crate::management_v2_revocation_state::preauthorized(value);
    }
    let (state, role, required, authority, excluded) = if let ManagementIntentV2::DeviceTransfer {
        target_device_ref,
        ..
    } = &value.prepared.intent
    {
        (
            ManagementOperationState::AwaitingTarget,
            RequiredActorRole::TargetDevice,
            Some(target_device_ref.as_str()),
            None,
            vec![value.prepared.source_device_ref.clone()],
        )
    } else {
        let requirements = value
            .prepared
            .revocation
            .as_ref()
            .ok_or(HostError::OperationInvalid)?;
        (
            ManagementOperationState::AwaitingIndependentApproval,
            RequiredActorRole::IndependentApproval,
            None,
            requirements.required_approval_authority_ref.as_deref(),
            vec![
                value.prepared.source_device_ref.clone(),
                requirements.target_device_ref.clone(),
            ],
        )
    };
    value.operation.state = state;
    value.operation.state_revision = next(value.operation.state_revision)?;
    value.operation.webauthn_options = None;
    value.operation.actor = actor(role, required, authority, excluded);
    Ok(())
}

pub(crate) fn actor(
    role: RequiredActorRole,
    device: Option<&str>,
    authority: Option<&str>,
    excluded: Vec<String>,
) -> ActorRequirementV2 {
    ActorRequirementV2 {
        role,
        required_actor_device_ref: device.map(str::to_owned),
        required_approval_authority_ref: authority.map(str::to_owned),
        excluded_actor_device_refs: excluded,
    }
}

pub(crate) fn transfer_target(value: &EndpointPreparedOperationV2) -> Result<&str, HostError> {
    match &value.intent {
        ManagementIntentV2::DeviceTransfer {
            target_device_ref, ..
        } => Ok(target_device_ref),
        _ => Err(HostError::OperationInvalid),
    }
}

fn next(value: u64) -> Result<u64, HostError> {
    value.checked_add(1).ok_or(HostError::StateInvalid)
}
