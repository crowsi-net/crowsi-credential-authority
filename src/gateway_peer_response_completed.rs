use crowsi_credential_authority_contracts::{
    ManagementOperationScopeV2, ManagementOperationState, ManagementProjectionBodyV2,
};

use crate::{HostError, gateway_peer_status::GatewayPeerStatus};

pub(crate) fn apply(
    status: &GatewayPeerStatus,
    projection: &crowsi_credential_authority_contracts::ManagementProjectionV2,
    now: u64,
) -> Result<(), HostError> {
    let ManagementProjectionBodyV2::Operation { operation } = &projection.body else {
        return Ok(());
    };
    if operation.state != ManagementOperationState::Completed {
        return Ok(());
    }
    if let ManagementOperationScopeV2::DeviceRevocation {
        target_device_ref,
        expected_device_revocation_epoch,
        ..
    } = &operation.scope
    {
        status.deny(
            target_device_ref,
            expected_device_revocation_epoch
                .checked_add(1)
                .ok_or(HostError::StateInvalid)?,
            now,
        )?;
    }
    Ok(())
}
