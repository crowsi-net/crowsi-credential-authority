use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointIndependentRevocationPreFinalProjectionTrustV1,
    decode_endpoint_independent_revocation_pre_final_request_strict,
    decode_management_projection_strict,
    verify_endpoint_independent_revocation_pre_final_projection_at,
};

use crate::{HostError, host_config_types::HostConfigDocument};

pub(crate) fn apply(
    trust: &HostConfigDocument,
    transport: &SignedRequest,
    response: &[u8],
    now: u64,
) -> Result<(), HostError> {
    let request =
        decode_endpoint_independent_revocation_pre_final_request_strict(&transport.payload)
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
    verify_endpoint_independent_revocation_pre_final_projection_at(
        &projection,
        &request,
        &transport.peer.device_id,
        &EndpointIndependentRevocationPreFinalProjectionTrustV1 {
            issuer: &trust.management_projection_issuer,
            audience: &trust.management_audience,
            key_id: &trust.management_projection_key_id,
            public_key_hex: &trust.management_projection_public_key_hex,
            minimum_snapshot_revision: 1,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::ResponseInvalid)
}
