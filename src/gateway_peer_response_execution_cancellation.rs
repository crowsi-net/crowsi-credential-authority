use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, EndpointRevocationExecutionCancellationTrustV1,
    decode_endpoint_revocation_execution_cancel_request_strict,
    decode_endpoint_revocation_execution_cancellation_strict,
    verify_endpoint_revocation_execution_cancellation_at,
};

use crate::{HostError, host_config_types::HostConfigDocument};

pub(crate) fn apply(
    trust: &HostConfigDocument,
    transport: &SignedRequest,
    response: &[u8],
    now: u64,
) -> Result<(), HostError> {
    let request = decode_endpoint_revocation_execution_cancel_request_strict(&transport.payload)
        .map_err(|_| HostError::ResponseInvalid)?;
    let EndpointManagementEvidenceV2::Cancel {
        identity_exchange, ..
    } = &request.cancel_envelope.evidence
    else {
        return Err(HostError::ResponseInvalid);
    };
    if !crate::gateway_peer_response_internal::current_mapping(
        trust,
        identity_exchange,
        &request.prepared.opaque_owner_ref,
        &transport.peer.device_id,
    ) {
        return Err(HostError::ResponseInvalid);
    }
    let cancellation = decode_endpoint_revocation_execution_cancellation_strict(response)
        .map_err(|_| HostError::ResponseInvalid)?;
    verify_endpoint_revocation_execution_cancellation_at(
        &cancellation,
        &request,
        &transport.peer.device_id,
        &EndpointRevocationExecutionCancellationTrustV1 {
            issuer: &trust.management_projection_issuer,
            audience: &trust.management_audience,
            key_id: &trust.management_projection_key_id,
            public_key_hex: &trust.management_projection_public_key_hex,
            minimum_config_generation: trust.revocation_execution_reservation_config_generation,
            cancellation_key_id: &trust.revocation_execution_reservation_key_id,
            cancellation_public_key_hex: &trust.revocation_execution_reservation_public_key_hex,
            minimum_cancellation_config_generation: trust
                .revocation_execution_reservation_config_generation,
            minimum_snapshot_revision: 1,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::ResponseInvalid)
}
