use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointIdentityTrustV2, ManagementProjectionBinding, ManagementProjectionBodyV2,
    ManagementProjectionV2, decode_endpoint_management_envelope_strict,
    decode_management_projection_strict, identity_evidence_from_exchange,
    management_command_digest, verify_management_projection_at,
};

use crate::{HostError, host_config_types::HostConfigDocument};

pub(crate) fn verify(
    trust: &HostConfigDocument,
    request: &SignedRequest,
    response: &[u8],
    now: u64,
) -> Result<Option<ManagementProjectionV2>, HostError> {
    let envelope = decode_endpoint_management_envelope_strict(&request.payload)
        .map_err(|_| HostError::ResponseInvalid)?;
    crate::management_v2_dispatch::command_matches(
        &request.command,
        &envelope.browser_request.command,
    )
    .map_err(invalid)?;
    if !crate::management_v2_command::historic_mutation(&envelope.browser_request.command) {
        return Ok(None);
    }
    let exchange = crate::gateway_peer_response::identity_exchange(&envelope.evidence);
    let identity = identity_evidence_from_exchange(exchange).map_err(invalid)?;
    if live(trust, exchange, identity, now) {
        return Ok(None);
    }
    let prepared = crate::gateway_peer_response::prepared(&envelope.evidence)
        .ok_or(HostError::ResponseInvalid)?;
    let projection = decode_management_projection_strict(response).map_err(invalid)?;
    let ManagementProjectionBodyV2::Operation { operation } = &projection.body else {
        return Err(HostError::ResponseInvalid);
    };
    let owner = trust.owner_mappings.iter().find(|item| {
        item.issuer == identity.assertion.issuer
            && item.service_id == identity.assertion.service_id
            && item.pairwise_subject == identity.assertion.pairwise_subject
    });
    if identity.assertion.device_id != request.peer.device_id
        || owner.is_none_or(|item| item.opaque_owner_ref != prepared.opaque_owner_ref)
        || !binding(&envelope.browser_request.command, prepared, operation)
    {
        return Err(HostError::ResponseInvalid);
    }
    let digest = management_command_digest(&envelope.browser_request).map_err(invalid)?;
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    verify_management_projection_at(
        &projection,
        &ManagementProjectionBinding {
            request_id: &envelope.browser_request.request_id,
            command_digest_sha256: &digest,
            issuer: &trust.management_projection_issuer,
            audience: &trust.management_audience,
            service_id: &assertion.service_id,
            pairwise_subject: &assertion.pairwise_subject,
            opaque_account_ref: &prepared.opaque_owner_ref,
            current_device_ref: &assertion.device_id,
            current_session_ref: &assertion.session_ref,
            subject_revocation_epoch: epochs.subject,
            service_revocation_epoch: epochs.service,
            device_revocation_epoch: epochs.device,
            session_revocation_epoch: epochs.session,
            device_posture_state: &assertion.device_posture.state,
            device_posture_revision: assertion.device_posture.revision,
            device_proof_key_ref: &assertion.device_proof_key_ref,
            minimum_snapshot_revision: 1,
        },
        &trust.management_projection_key_id,
        &trust.management_projection_public_key_hex,
        now,
    )
    .map_err(invalid)?;
    Ok(Some(projection))
}

fn invalid<T>(_: T) -> HostError {
    HostError::ResponseInvalid
}

include!("gateway_peer_response_mutation_identity.rs");
include!("gateway_peer_response_mutation_binding.rs");
