use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, ManagementOperationKind,
    ManagementOperationScopeV2, ManagementSnapshotV2,
};

use crate::{HostError, host_config::VerifiedHostConfig};

pub(crate) fn scope(
    config: &VerifiedHostConfig,
    prepared: &EndpointPreparedOperationV2,
    snapshot: &ManagementSnapshotV2,
) -> Result<(ManagementOperationKind, ManagementOperationScopeV2), HostError> {
    match &prepared.intent {
        ManagementIntentV2::DeviceTransfer {
            service_id,
            target_device_ref,
            credential_refs,
            ..
        } => transfer(
            prepared,
            snapshot,
            service_id,
            target_device_ref,
            credential_refs,
        ),
        ManagementIntentV2::DeviceRevocation {
            target_device_ref,
            expected_device_revocation_epoch,
            ..
        } => crate::management_v2_operation_revocation::revoke_device(
            config,
            prepared,
            snapshot,
            target_device_ref,
            *expected_device_revocation_epoch,
        ),
        ManagementIntentV2::SessionRevocation {
            target_session_ref,
            expected_session_revocation_epoch,
            ..
        } => crate::management_v2_operation_revocation::revoke_session(
            config,
            prepared,
            snapshot,
            target_session_ref,
            *expected_session_revocation_epoch,
        ),
    }
}

fn transfer(
    prepared: &EndpointPreparedOperationV2,
    snapshot: &ManagementSnapshotV2,
    service_id: &str,
    target_device_ref: &str,
    credential_refs: &[String],
) -> Result<(ManagementOperationKind, ManagementOperationScopeV2), HostError> {
    let source =
        crate::management_v2_operation_policy::device(snapshot, &prepared.source_device_ref)?;
    crate::management_v2_operation_policy::device(snapshot, target_device_ref)?;
    if credential_refs.len() != 1
        || credential_refs.iter().any(|id| {
            !snapshot.credentials.iter().any(|item| {
                &item.credential_ref == id
                    && item.provider == service_id
                    && item.status
                        == crowsi_credential_authority_contracts::ManagementLifecycleV2::Active
                    && item
                        .assigned_device_refs
                        .contains(&prepared.source_device_ref)
            })
        })
    {
        return Err(HostError::OperationInvalid);
    }
    Ok((
        ManagementOperationKind::DeviceTransfer,
        ManagementOperationScopeV2::DeviceTransfer {
            target_device_ref: target_device_ref.to_owned(),
            credential_refs: credential_refs.to_vec(),
            expected_source_device_revocation_epoch: source.device_revocation_epoch,
        },
    ))
}
