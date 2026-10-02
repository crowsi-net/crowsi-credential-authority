use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementOperationKind, ManagementOperationScopeV2,
    ManagementSnapshotV2,
};

use crate::{HostError, host_config::VerifiedHostConfig};

pub(crate) fn revoke_device(
    config: &VerifiedHostConfig,
    prepared: &EndpointPreparedOperationV2,
    snapshot: &ManagementSnapshotV2,
    target_device_ref: &str,
    expected_epoch: u64,
) -> Result<(ManagementOperationKind, ManagementOperationScopeV2), HostError> {
    let target = crate::management_v2_operation_policy::device(snapshot, target_device_ref)?;
    let requirements = crate::management_v2_operation_policy::requirements(config, prepared)?;
    let active_sessions = snapshot
        .sessions
        .iter()
        .filter(|item| {
            item.device_ref == target_device_ref
                && item.status
                    == crowsi_credential_authority_contracts::ManagementLifecycleV2::Active
        })
        .map(|item| item.session_ref.clone())
        .collect::<Vec<_>>();
    if target.device_revocation_epoch != expected_epoch
        || requirements.target_device_ref != target_device_ref
        || requirements.expected_revoked_session_count != Some(active_sessions.len() as u64)
    {
        return Err(HostError::OperationInvalid);
    }
    let rotations = snapshot
        .credentials
        .iter()
        .filter(|item| {
            item.provider == crate::management_v2_operation_policy::prepared_service(prepared)
                && item.status
                    == crowsi_credential_authority_contracts::ManagementLifecycleV2::Active
                && item
                    .assigned_device_refs
                    .iter()
                    .any(|id| id == target_device_ref)
        })
        .map(|item| item.credential_ref.clone())
        .collect();
    let preserves = snapshot
        .devices
        .iter()
        .filter(|item| {
            item.device_ref != target_device_ref
                && item.status
                    == crowsi_credential_authority_contracts::ManagementLifecycleV2::Active
        })
        .map(|item| item.device_ref.clone())
        .collect();
    Ok((
        ManagementOperationKind::DeviceRevocation,
        ManagementOperationScopeV2::DeviceRevocation {
            target_device_ref: target_device_ref.to_owned(),
            expected_device_revocation_epoch: expected_epoch,
            revokes_session_refs: active_sessions,
            rotates_credential_refs: rotations,
            preserves_device_refs: preserves,
        },
    ))
}

pub(crate) fn revoke_session(
    config: &VerifiedHostConfig,
    prepared: &EndpointPreparedOperationV2,
    snapshot: &ManagementSnapshotV2,
    target_session_ref: &str,
    expected_epoch: u64,
) -> Result<(ManagementOperationKind, ManagementOperationScopeV2), HostError> {
    let session = snapshot
        .sessions
        .iter()
        .find(|item| item.session_ref == target_session_ref)
        .ok_or(HostError::OperationInvalid)?;
    let requirements = crate::management_v2_operation_policy::requirements(config, prepared)?;
    if session.status != crowsi_credential_authority_contracts::ManagementLifecycleV2::Active
        || session.session_revocation_epoch != expected_epoch
        || requirements.target_device_ref != session.device_ref
        || requirements.expected_revoked_session_count.is_some()
    {
        return Err(HostError::OperationInvalid);
    }
    Ok((
        ManagementOperationKind::SessionRevocation,
        ManagementOperationScopeV2::SessionRevocation {
            target_session_ref: target_session_ref.to_owned(),
            expected_session_revocation_epoch: expected_epoch,
            device_ref: session.device_ref.clone(),
        },
    ))
}
