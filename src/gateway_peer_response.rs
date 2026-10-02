use crate::{
    HostError, gateway_peer_status::GatewayPeerStatus, host_config_types::HostConfigDocument,
};
use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointIdentityTrustV2, EndpointManagementEvidenceV2, ManagementProjectionBinding,
    SignedAuthorityExchangeV1, decode_endpoint_management_envelope_strict,
    decode_management_projection_strict, identity_evidence_from_exchange,
    management_command_digest, verify_authority_exchange_at, verify_endpoint_identity_at,
    verify_management_projection_at,
};

pub(crate) fn apply(
    status: &GatewayPeerStatus,
    trust: &HostConfigDocument,
    request: &SignedRequest,
    response: &[u8],
    now: u64,
) -> Result<(), HostError> {
    if request.command == "lookup-prepared" {
        return Ok(());
    }
    if request.command == "revocation-finalize" {
        return crate::gateway_peer_response_finalize::apply(status, trust, request, response, now);
    }
    if request.command == "independent-revocation-finalize" {
        return crate::gateway_peer_response_independent_finalize::apply(
            status, trust, request, response, now,
        );
    }
    if request.command == "independent-revocation-pre-final" {
        return crate::gateway_peer_response_independent_pre_final::apply(
            trust, request, response, now,
        );
    }
    if request.command == "revocation-execution-reserve" {
        return crate::gateway_peer_response_execution_reservation::apply(
            trust, request, response, now,
        );
    }
    if request.command == "revocation-execution-cancel" {
        return crate::gateway_peer_response_execution_cancellation::apply(
            trust, request, response, now,
        );
    }
    if request.command == "revocation-execution-cancel-finalize" {
        return crate::gateway_peer_response_execution_cancellation_cleanup::apply(
            trust, request, response, now,
        );
    }
    if request.command == "revocation-execution-cancel-cleanup-complete" {
        return crate::gateway_peer_response_execution_cancellation_cleanup_complete::apply(
            trust, request, response, now,
        );
    }
    if crate::gateway_peer_response_cancel::apply(trust, request, response, now)? {
        return Ok(());
    }
    if crate::gateway_peer_response_pre_final::apply(trust, request, response, now)? {
        return Ok(());
    }
    if let Some(projection) =
        crate::gateway_peer_response_mutation::verify(trust, request, response, now)?
    {
        return crate::gateway_peer_response_completed::apply(status, &projection, now);
    }
    let envelope = decode_endpoint_management_envelope_strict(&request.payload)
        .map_err(|_| HostError::ResponseInvalid)?;
    let identity_exchange = identity_exchange(&envelope.evidence);
    verify_authority_exchange_at(
        identity_exchange,
        "issue_current_device_identity_evidence",
        trust.minimum_identity_config_generation,
        &trust.identity_response_key_id,
        &trust.identity_response_public_key_hex,
        now,
    )
    .map_err(|_| HostError::ResponseInvalid)?;
    let identity = identity_evidence_from_exchange(identity_exchange)
        .map_err(|_| HostError::ResponseInvalid)?;
    verify_endpoint_identity_at(
        identity,
        &EndpointIdentityTrustV2 {
            issuer: &trust.identity_issuer,
            audience: &trust.management_audience,
            assertion_key_id: &trust.identity_key_id,
            assertion_public_key_hex: &trust.identity_public_key_hex,
            current_status_key_id: &trust.current_status_key_id,
            current_status_public_key_hex: &trust.current_status_public_key_hex,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::ResponseInvalid)?;
    if identity.assertion.device_id != request.peer.device_id {
        return Err(HostError::ResponseInvalid);
    }
    let owner = trust
        .owner_mappings
        .iter()
        .find(|item| {
            item.issuer == identity.assertion.issuer
                && item.service_id == identity.assertion.service_id
                && item.pairwise_subject == identity.assertion.pairwise_subject
        })
        .ok_or(HostError::ResponseInvalid)?;
    let projection =
        decode_management_projection_strict(response).map_err(|_| HostError::ResponseInvalid)?;
    let digest = management_command_digest(&envelope.browser_request)
        .map_err(|_| HostError::ResponseInvalid)?;
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
            opaque_account_ref: &owner.opaque_owner_ref,
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
    .map_err(|_| HostError::ResponseInvalid)?;
    crate::gateway_peer_response_completed::apply(status, &projection, now)
}

include!("gateway_peer_response_evidence.rs");
