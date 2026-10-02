use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, EndpointRevocationExecutionCancelRequestV1,
    EndpointRevocationExecutionCancellationV1,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityRequestV1, CancelPendingRevocationCommand,
    SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole, canonical_signed_evidence,
    command_digest,
};

use crate::{HostError, host_config::VerifiedHostConfig};

pub(crate) fn build(
    config: &VerifiedHostConfig,
    request: &EndpointRevocationExecutionCancelRequestV1,
    operation: crowsi_credential_authority_contracts::ManagementOperationV2,
    snapshot_revision: u64,
    now: u64,
) -> Result<EndpointRevocationExecutionCancellationV1, HostError> {
    let identity = cancel_identity(request)?;
    let begun = begun(request)?;
    let cancel_pending_request = authority_request(config, request, identity, begun)?;
    let mut value = EndpointRevocationExecutionCancellationV1 {
        schema: crowsi_credential_authority_contracts::ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_SCHEMA.into(),
        cancellation_id: String::new(),
        cancellation_request_sha256: crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_request_digest(request)
            .map_err(|_| HostError::RequestInvalid)?,
        cancel_envelope_digest_sha256: crowsi_credential_authority_contracts::endpoint_revocation_cancel_envelope_digest(&request.cancel_envelope)
            .map_err(|_| HostError::RequestInvalid)?,
        pre_final_acceptance_request_sha256: request.pre_final_acceptance_request_sha256.clone(),
        prepared_operation_digest_sha256: crowsi_credential_authority_contracts::endpoint_operation_digest(&request.prepared)
            .map_err(|_| HostError::RequestInvalid)?,
        opaque_owner_ref: request.prepared.opaque_owner_ref.clone(),
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        source_device_ref: request.prepared.source_device_ref.clone(),
        source_session_ref: request.prepared.source_session_ref.clone(),
        target_digest_sha256: begun.target_digest.clone(),
        begin_exchange_digest_sha256: crowsi_credential_authority_contracts::endpoint_signed_authority_exchange_digest(&request.begin_exchange)
            .map_err(|_| HostError::RequestInvalid)?,
        begin_command_digest_sha256: command_digest(&request.begin_exchange.request)
            .map_err(|_| HostError::RequestInvalid)?,
        finalize_command_id: request.operation_id.clone(),
        cancelled_state_revision: request.expected_cancelled_state_revision,
        execution_reservation_id: None,
        cancellation_config_generation: config.document.revocation_execution_reservation_config_generation,
        cancellation_accepted_revision: snapshot_revision,
        operation,
        snapshot_revision,
        cancel_pending_request,
        token: empty_token(config, now),
        issuer: config.document.management_projection_issuer.clone(),
        audience: config.document.management_audience.clone(),
        config_generation: config.document.revocation_execution_reservation_config_generation,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(30),
        key_id: config.document.management_projection_key_id.clone(),
        signature: String::new(),
    };
    sign(config, &mut value)?;
    Ok(value)
}

include!("management_v2_execution_cancellation_build_support.rs");
