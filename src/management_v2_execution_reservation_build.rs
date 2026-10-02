use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionReservationV1, EndpointRevocationExecutionReserveRequestV1,
    ManagementOperationV2,
};
use ihat_identity_assertion_contracts::{
    SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole, canonical_signed_evidence,
    command_digest,
};

use crate::{HostError, host_config::VerifiedHostConfig};

pub(crate) fn build(
    config: &VerifiedHostConfig,
    request: &EndpointRevocationExecutionReserveRequestV1,
    operation: ManagementOperationV2,
    snapshot_revision: u64,
    now: u64,
) -> Result<EndpointRevocationExecutionReservationV1, HostError> {
    let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(
        &request.accepted_identity_exchange,
    )
    .map_err(|_| HostError::EvidenceInvalid)?;
    let target = begin_target(request, now)?;
    let mut value = EndpointRevocationExecutionReservationV1 {
        schema: crowsi_credential_authority_contracts::ENDPOINT_REVOCATION_EXECUTION_RESERVATION_SCHEMA.into(),
        reservation_id: String::new(),
        reservation_request_sha256: crowsi_credential_authority_contracts::endpoint_revocation_execution_reserve_request_digest(request)
            .map_err(|_| HostError::RequestInvalid)?,
        original_request_id: request.original_request.request_id.clone(),
        original_command_digest_sha256: crowsi_credential_authority_contracts::management_command_digest(&request.original_request)
            .map_err(|_| HostError::RequestInvalid)?,
        prepared_operation_digest_sha256: crowsi_credential_authority_contracts::endpoint_operation_digest(&request.prepared)
            .map_err(|_| HostError::RequestInvalid)?,
        reconcile_digest: request.reconcile_digest.clone(),
        opaque_owner_ref: request.prepared.opaque_owner_ref.clone(),
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        source_device_ref: request.prepared.source_device_ref.clone(),
        finalizer_device_ref: identity.assertion.device_id.clone(),
        target_digest_sha256: target,
        begin_exchange_digest_sha256: crowsi_credential_authority_contracts::endpoint_signed_authority_exchange_digest(&request.begin_exchange)
            .map_err(|_| HostError::RequestInvalid)?,
        approval_exchange_digest_sha256: request.approval_exchange.as_ref().map(
            crowsi_credential_authority_contracts::endpoint_signed_authority_exchange_digest,
        ).transpose().map_err(|_| HostError::RequestInvalid)?,
        final_command_digest_sha256: command_digest(&request.final_revoke_request)
            .map_err(|_| HostError::RequestInvalid)?,
        pre_final_state_revision: request.expected_state_revision,
        reserved_state_revision: operation.state_revision,
        reservation_config_generation: config.document.revocation_execution_reservation_config_generation,
        operation,
        snapshot_revision,
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

include!("management_v2_execution_reservation_build_support.rs");
