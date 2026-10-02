use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointIndependentRevocationFinalizeProjectionTrustV1, ManagementOperationScopeV2,
    ManagementOperationState, ManagementProjectionBodyV2,
    decode_endpoint_independent_revocation_finalize_request_strict,
    decode_management_projection_strict,
    verify_endpoint_independent_revocation_finalize_projection_at,
};

use crate::{
    HostError, gateway_peer_status::GatewayPeerStatus, host_config_types::HostConfigDocument,
};

pub(crate) fn apply(
    status: &GatewayPeerStatus,
    trust: &HostConfigDocument,
    transport: &SignedRequest,
    response: &[u8],
    now: u64,
) -> Result<(), HostError> {
    let request =
        decode_endpoint_independent_revocation_finalize_request_strict(&transport.payload)
            .map_err(|_| HostError::ResponseInvalid)?;
    if !crate::gateway_peer_response_internal::current_mapping(
        trust,
        &request.accepted_identity_exchange,
        &request.prepared.opaque_owner_ref,
        &transport.peer.device_id,
    ) {
        return Err(HostError::ResponseInvalid);
    }
    let projection =
        decode_management_projection_strict(response).map_err(|_| HostError::ResponseInvalid)?;
    verify_endpoint_independent_revocation_finalize_projection_at(
        &projection,
        &request,
        &transport.peer.device_id,
        &EndpointIndependentRevocationFinalizeProjectionTrustV1 {
            issuer: &trust.management_projection_issuer,
            audience: &trust.management_audience,
            key_id: &trust.management_projection_key_id,
            public_key_hex: &trust.management_projection_public_key_hex,
            minimum_snapshot_revision: 1,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::ResponseInvalid)?;
    let ManagementProjectionBodyV2::Operation { operation } = &projection.body else {
        return Err(HostError::ResponseInvalid);
    };
    if matches!(
        operation.state,
        ManagementOperationState::Unknown | ManagementOperationState::Completed
    ) && let ManagementOperationScopeV2::DeviceRevocation {
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
