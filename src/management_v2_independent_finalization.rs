use crate::{
    HostError,
    host_config::VerifiedHostConfig,
    management_v2_record::{
        IndependentRevocationFinalizationAcceptanceV1 as Acceptance, ManagementRecordV2,
    },
};

pub(crate) fn preauthorize(
    value: &ManagementRecordV2,
    request: &crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1,
    config: &VerifiedHostConfig,
    now: u64,
    snapshot_revision: u64,
) -> Result<Acceptance, HostError> {
    exact(value, request, config)?;
    let request_digest = crowsi_credential_authority_contracts::endpoint_independent_revocation_pre_final_request_digest(request)
        .map_err(|_| HostError::RequestInvalid)?;
    let reconcile_digest = reconcile_digest(value, &request_digest, request)?;
    Ok(Acceptance {
        accepted_at_epoch_s: now,
        pre_final_state_revision: value
            .operation
            .state_revision
            .checked_add(1)
            .ok_or(HostError::StateInvalid)?,
        pre_final_snapshot_revision: snapshot_revision,
        pre_final_request_sha256: request_digest,
        reconcile_digest,
        pre_final_request: Box::new(request.clone()),
        accepted_identity_exchange: request.accepted_identity_exchange.clone(),
        selected_identity_exchange: request.selected_identity_exchange.clone(),
        begin_uv_exchange: request.begin_uv_exchange.clone(),
        finish_uv_exchange: request.finish_uv_exchange.clone(),
        begin_exchange: request.revocation_ceremony.begin.clone(),
        approval_exchange: request.revocation_ceremony.approval.clone(),
        response_key_id: config.document.identity_response_key_id.clone(),
        response_public_key_hex: config.document.identity_response_public_key_hex.clone(),
        minimum_config_generation: value.authority_config_generation,
        cancellation_slot_reserved: false,
        cancellation_cleanup_completed: false,
        cancellation_cleanup_delivery_completed: false,
        cancellation_recovery_reservation_bytes: 0,
        execution_reservation: None,
        execution_cancellation: None,
        finalize_request_sha256: None,
        finalize_request: None,
        final_revoke_exchange: None,
    })
}

fn exact(
    value: &ManagementRecordV2,
    request: &crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1,
    config: &VerifiedHostConfig,
) -> Result<(), HostError> {
    let requirements = value
        .prepared
        .revocation
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let valid = requirements.target_device_ref != value.prepared.source_device_ref
        && value.prepared == request.prepared
        && value.operation.operation_id == request.operation_id
        && value.actor_options_identity_exchange.as_ref()
            == Some(&request.selected_identity_exchange)
        && value.actor_options_exchange.as_ref() == Some(&request.begin_uv_exchange)
        && value
            .source_revocation_ceremony
            .as_ref()
            .is_some_and(|item| item.begin == request.revocation_ceremony.begin)
        && request.revocation_ceremony.begin.response.key_id
            == config.document.identity_response_key_id
        && request.revocation_ceremony.approval.response.key_id
            == config.document.identity_response_key_id
        && value.authority_config_generation
            >= request
                .revocation_ceremony
                .approval
                .response
                .config_generation
        && value.authority_config_generation
            >= request
                .accepted_identity_exchange
                .response
                .config_generation;
    valid.then_some(()).ok_or(HostError::StateInvalid)
}

fn reconcile_digest(
    value: &ManagementRecordV2,
    request_digest: &str,
    request: &crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1,
) -> Result<String, HostError> {
    let wire = serde_json::to_vec(&(
        "CROWSI-MANAGEMENT-INDEPENDENT-REVOCATION-FINALIZE-V1",
        &value.operation.operation_id,
        &value.prepared,
        request_digest,
        crate::management_v2_journal_policy::exchange_digest(&request.revocation_ceremony.begin)?,
        crate::management_v2_journal_policy::exchange_digest(
            &request.revocation_ceremony.approval,
        )?,
    ))
    .map_err(|_| HostError::StateInvalid)?;
    Ok(crate::host_crypto::digest(&wire)
        .trim_start_matches("sha256:")
        .to_owned())
}
