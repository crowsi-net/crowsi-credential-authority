use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointRevocationPreFinalProjectionTrustV1, ManagementOperationState,
    ManagementProjectionBodyV2, decode_endpoint_management_envelope_strict,
    decode_management_projection_strict, verify_endpoint_revocation_pre_final_projection_at,
};

use crate::{HostError, host_config_types::HostConfigDocument};

pub(crate) fn apply(
    trust: &HostConfigDocument,
    request: &SignedRequest,
    response: &[u8],
    now: u64,
) -> Result<bool, HostError> {
    if request.command != "source-approve" {
        return Ok(false);
    }
    let projection =
        decode_management_projection_strict(response).map_err(|_| HostError::ResponseInvalid)?;
    let ManagementProjectionBodyV2::Operation { operation } = &projection.body else {
        return Ok(false);
    };
    if operation.state != ManagementOperationState::AwaitingRevocationFinal {
        return Ok(false);
    }
    let envelope = decode_endpoint_management_envelope_strict(&request.payload)
        .map_err(|_| HostError::ResponseInvalid)?;
    verify_endpoint_revocation_pre_final_projection_at(
        &projection,
        &envelope,
        &request.peer.device_id,
        &EndpointRevocationPreFinalProjectionTrustV1 {
            issuer: &trust.management_projection_issuer,
            audience: &trust.management_audience,
            key_id: &trust.management_projection_key_id,
            public_key_hex: &trust.management_projection_public_key_hex,
            minimum_snapshot_revision: 1,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::ResponseInvalid)?;
    Ok(true)
}
