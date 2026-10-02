use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancelFinalizeRequestV1,
    EndpointRevocationExecutionCancellationCleanupV1,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AcknowledgePendingCancellationCommand, AuthorityCommand,
    AuthorityRequestV1, SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole,
    canonical_signed_evidence, command_digest,
};

use crate::{HostError, host_config::VerifiedHostConfig};

pub(crate) fn build(
    config: &VerifiedHostConfig,
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    operation: crowsi_credential_authority_contracts::ManagementOperationV2,
    snapshot_revision: u64,
    now: u64,
) -> Result<EndpointRevocationExecutionCancellationCleanupV1, HostError> {
    let request_digest = request_digest(request)?;
    let command_digest = authority_command_digest(request)?;
    let response_digest = response_digest(request)?;
    let acknowledge_request = authority_request(
        config,
        request,
        &request_digest,
        &command_digest,
        &response_digest,
        snapshot_revision,
    );
    let mut value = EndpointRevocationExecutionCancellationCleanupV1 {
        schema: crowsi_credential_authority_contracts::ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_CLEANUP_SCHEMA.into(),
        cleanup_id: String::new(),
        cancel_finalize_request_sha256: request_digest,
        cancellation_id: request.cancellation.cancellation_id.clone(),
        cancel_pending_command_digest_sha256: command_digest,
        cancel_pending_response_digest_sha256: response_digest,
        source_device_ref: request.cancellation_request.prepared.source_device_ref.clone(),
        cleanup_completed_revision: snapshot_revision,
        cleanup_config_generation: config.document.revocation_execution_reservation_config_generation,
        operation,
        snapshot_revision,
        acknowledge_request,
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

include!("management_v2_execution_cancellation_cleanup_build_support.rs");
