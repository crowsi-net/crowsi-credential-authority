use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, ManagementSnapshotV2,
};

use crate::{HostError, host_config::VerifiedHostConfig};

pub(crate) fn prepared_service(value: &EndpointPreparedOperationV2) -> &str {
    match &value.intent {
        ManagementIntentV2::DeviceTransfer { service_id, .. }
        | ManagementIntentV2::DeviceRevocation { service_id, .. }
        | ManagementIntentV2::SessionRevocation { service_id, .. } => service_id,
    }
}

pub(crate) fn requirements<'a>(
    config: &VerifiedHostConfig,
    value: &'a EndpointPreparedOperationV2,
) -> Result<&'a crowsi_credential_authority_contracts::RevocationRequirementsV2, HostError> {
    let requirements = value
        .revocation
        .as_ref()
        .ok_or(HostError::OperationInvalid)?;
    if requirements.finalization_authority_id != config.document.identity_finalization_authority_id
        || requirements
            .required_approval_authority_ref
            .as_ref()
            .is_some_and(|item| {
                !config
                    .document
                    .revocation_approval_authority_refs
                    .contains(item)
            })
    {
        Err(HostError::OperationInvalid)
    } else {
        Ok(requirements)
    }
}

pub(crate) fn device<'a>(
    snapshot: &'a ManagementSnapshotV2,
    id: &str,
) -> Result<&'a crowsi_credential_authority_contracts::ManagementDeviceV2, HostError> {
    snapshot
        .devices
        .iter()
        .find(|item| {
            item.device_ref == id
                && item.status
                    == crowsi_credential_authority_contracts::ManagementLifecycleV2::Active
        })
        .ok_or(HostError::OperationInvalid)
}
