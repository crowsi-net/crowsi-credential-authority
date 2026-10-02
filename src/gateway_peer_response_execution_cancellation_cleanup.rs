use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, EndpointRevocationExecutionCancellationCleanupTrustV1,
    decode_endpoint_revocation_execution_cancel_finalize_request_strict,
    decode_endpoint_revocation_execution_cancellation_cleanup_strict,
    verify_endpoint_revocation_execution_cancellation_cleanup_at,
};

use crate::{HostError, host_config_types::HostConfigDocument};

pub(crate) fn apply(
    trust: &HostConfigDocument,
    transport: &SignedRequest,
    response: &[u8],
    now: u64,
) -> Result<(), HostError> {
    let request =
        decode_endpoint_revocation_execution_cancel_finalize_request_strict(&transport.payload)
            .map_err(|_| HostError::ResponseInvalid)?;
    let EndpointManagementEvidenceV2::Cancel {
        identity_exchange, ..
    } = &request.cancellation_request.cancel_envelope.evidence
    else {
        return Err(HostError::ResponseInvalid);
    };
    if !crate::gateway_peer_response_internal::current_mapping(
        trust,
        identity_exchange,
        &request.cancellation_request.prepared.opaque_owner_ref,
        &transport.peer.device_id,
    ) {
        return Err(HostError::ResponseInvalid);
    }
    let cleanup = decode_endpoint_revocation_execution_cancellation_cleanup_strict(response)
        .map_err(|_| HostError::ResponseInvalid)?;
    verify_endpoint_revocation_execution_cancellation_cleanup_at(
        &cleanup,
        &request,
        &request.cancellation,
        &transport.peer.device_id,
        &EndpointRevocationExecutionCancellationCleanupTrustV1 {
            issuer: &trust.management_projection_issuer,
            audience: &trust.management_audience,
            key_id: &trust.management_projection_key_id,
            public_key_hex: &trust.management_projection_public_key_hex,
            minimum_config_generation: trust.revocation_execution_reservation_config_generation,
            cleanup_key_id: &trust.revocation_execution_reservation_key_id,
            cleanup_public_key_hex: &trust.revocation_execution_reservation_public_key_hex,
            minimum_cleanup_config_generation: trust
                .revocation_execution_reservation_config_generation,
            minimum_snapshot_revision: request.cancellation.snapshot_revision,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::ResponseInvalid)
}
