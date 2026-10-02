use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    EndpointRevocationExecutionCancellationCleanupCompleteV1,
};
use ihat_identity_assertion_contracts::{
    SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole, canonical_signed_evidence,
};

use crate::{HostError, host_config::VerifiedHostConfig};

pub(crate) fn build(
    config: &VerifiedHostConfig,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    operation: crowsi_credential_authority_contracts::ManagementOperationV2,
    snapshot_revision: u64,
    now: u64,
) -> Result<EndpointRevocationExecutionCancellationCleanupCompleteV1, HostError> {
    let request_digest =
        crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_cleanup_complete_request_digest(request)
            .map_err(|_| HostError::RequestInvalid)?;
    let command_digest =
        ihat_identity_assertion_contracts::command_digest(&request.acknowledge_exchange.request)
            .map_err(|_| HostError::RequestInvalid)?;
    let result_digest = crowsi_credential_authority_contracts::endpoint_revocation_cancellation_acknowledgement_result_digest(request)
        .map_err(|_| HostError::RequestInvalid)?;
    let root_generation = config
        .document
        .revocation_execution_reservation_config_generation;
    let mut value = EndpointRevocationExecutionCancellationCleanupCompleteV1 {
        schema: crowsi_credential_authority_contracts::ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_CLEANUP_COMPLETE_SCHEMA.into(),
        cleanup_complete_id: String::new(),
        cleanup_complete_request_sha256: request_digest.clone(),
        cleanup_id: request.cleanup.cleanup_id.clone(),
        cancellation_id: request.cleanup.cancellation_id.clone(),
        acknowledge_command_digest_sha256: command_digest,
        acknowledge_result_digest_sha256: result_digest,
        source_device_ref: request.cleanup.source_device_ref.clone(),
        cleanup_delivery_completed_revision: snapshot_revision,
        cleanup_complete_config_generation: root_generation,
        operation,
        snapshot_revision,
        token: empty_token(config, request_digest, now),
        issuer: config.document.management_projection_issuer.clone(),
        audience: config.document.management_audience.clone(),
        config_generation: root_generation,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(30),
        key_id: config.document.management_projection_key_id.clone(),
        signature: String::new(),
    };
    sign(config, &mut value)?;
    Ok(value)
}

fn empty_token(config: &VerifiedHostConfig, binding: String, now: u64) -> SignedEvidenceV1 {
    SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::RevocationCancellationCleanupComplete,
        proof_id: String::new(),
        key_id: config
            .document
            .revocation_execution_reservation_key_id
            .clone(),
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(120),
        binding_sha256: binding,
        signature: String::new(),
    }
}

fn sign(
    config: &VerifiedHostConfig,
    value: &mut EndpointRevocationExecutionCancellationCleanupCompleteV1,
) -> Result<(), HostError> {
    value.cleanup_complete_id = crowsi_credential_authority_contracts::endpoint_revocation_execution_cancellation_cleanup_complete_id(value)
        .map_err(|_| HostError::ResponseInvalid)?;
    value.token.proof_id.clone_from(&value.cleanup_complete_id);
    value.token.signature = crate::host_crypto::sign(
        &config.revocation_execution_reservation_signing_key,
        &canonical_signed_evidence(&value.token).map_err(|_| HostError::ResponseInvalid)?,
    );
    value.signature = crate::host_crypto::sign(
        &config.management_projection_signing_key,
        &crowsi_credential_authority_contracts::canonical_endpoint_revocation_execution_cancellation_cleanup_complete(value)
            .map_err(|_| HostError::ResponseInvalid)?,
    );
    Ok(())
}
