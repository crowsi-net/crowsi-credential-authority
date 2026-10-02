use crowsi_credential_authority_contracts::{
    ActorRequirementV2, EndpointPreparedOperationV2, ManagementIntentV2, ManagementOperationState,
    ManagementOperationV2, ManagementSnapshotV2, RequiredActorRole, WebAuthnOptionsV2,
};

use crate::{HostError, host_config::VerifiedHostConfig};

pub(crate) fn initial(
    config: &VerifiedHostConfig,
    prepared: &EndpointPreparedOperationV2,
    snapshot: &ManagementSnapshotV2,
    options: WebAuthnOptionsV2,
    snapshot_revision: u64,
    now: u64,
) -> Result<ManagementOperationV2, HostError> {
    let expected_revision = match &prepared.intent {
        ManagementIntentV2::DeviceTransfer {
            expected_snapshot_revision,
            ..
        }
        | ManagementIntentV2::DeviceRevocation {
            expected_snapshot_revision,
            ..
        }
        | ManagementIntentV2::SessionRevocation {
            expected_snapshot_revision,
            ..
        } => *expected_snapshot_revision,
    };
    if expected_revision != snapshot_revision {
        return Err(HostError::StateInvalid);
    }
    let (kind, scope) = crate::management_v2_operation_scope::scope(config, prepared, snapshot)?;
    Ok(ManagementOperationV2 {
        operation_id: prepared.operation_id.clone(),
        kind,
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingSourceUv,
        state_revision: 1,
        created_at_epoch_s: now,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: prepared.source_device_ref.clone(),
        scope,
        actor: ActorRequirementV2 {
            role: RequiredActorRole::SourceDevice,
            required_actor_device_ref: Some(prepared.source_device_ref.clone()),
            required_approval_authority_ref: None,
            excluded_actor_device_refs: Vec::new(),
        },
        webauthn_options: Some(options),
        reason: None,
        reconcile_digest: None,
    })
}

pub(crate) fn grant_action(
    value: &EndpointPreparedOperationV2,
    snapshot: &ManagementSnapshotV2,
) -> Result<Option<String>, HostError> {
    let ManagementIntentV2::DeviceTransfer {
        credential_refs, ..
    } = &value.intent
    else {
        return Ok(None);
    };
    let [credential] = credential_refs.as_slice() else {
        return Err(HostError::OperationInvalid);
    };
    let value = snapshot
        .credentials
        .iter()
        .find(|item| &item.credential_ref == credential)
        .ok_or(HostError::OperationInvalid)?;
    let [action] = value.scopes.as_slice() else {
        return Err(HostError::OperationInvalid);
    };
    Ok(Some(action.clone()))
}
