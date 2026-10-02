use crate::{
    HostError,
    host_config::VerifiedHostConfig,
    management_v2_record::{ManagementRecordV2, RevocationFinalizationAcceptanceV1},
};

pub(crate) fn preauthorize(
    value: &ManagementRecordV2,
    source_approve_request: &crowsi_credential_authority_contracts::ManagementRequestV2,
    config: &VerifiedHostConfig,
    now: u64,
    snapshot_revision: u64,
) -> Result<RevocationFinalizationAcceptanceV1, HostError> {
    let requirements = value
        .prepared
        .revocation
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let identity = value
        .source_approval_identity_exchange
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let ceremony = value
        .source_revocation_ceremony
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    let request = value
        .source_approval_acceptance_sha256
        .as_ref()
        .ok_or(HostError::StateInvalid)?;
    if requirements.target_device_ref != value.prepared.source_device_ref
        || ceremony.final_revoke.is_some()
        || ceremony.begin.response.key_id != config.document.identity_response_key_id
        || value.authority_config_generation < ceremony.begin.response.config_generation
        || value.authority_config_generation < identity.response.config_generation
    {
        return Err(HostError::StateInvalid);
    }
    let request_digest = request
        .strip_prefix("sha256:")
        .ok_or(HostError::StateInvalid)?;
    let reconcile_digest = reconcile_digest(value, request_digest, &ceremony.begin)?;
    Ok(RevocationFinalizationAcceptanceV1 {
        accepted_at_epoch_s: now,
        pre_final_state_revision: value
            .operation
            .state_revision
            .checked_add(1)
            .ok_or(HostError::StateInvalid)?,
        pre_final_snapshot_revision: snapshot_revision,
        source_approve_request_sha256: request_digest.into(),
        reconcile_digest,
        source_approve_request: source_approve_request.clone(),
        accepted_identity_exchange: identity.clone(),
        begin_exchange: ceremony.begin.clone(),
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

fn reconcile_digest(
    value: &ManagementRecordV2,
    request: &str,
    begin: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> Result<String, HostError> {
    let wire = serde_json::to_vec(&(
        "CROWSI-MANAGEMENT-REVOCATION-FINALIZE-V1",
        &value.operation.operation_id,
        &value.prepared,
        request,
        crate::management_v2_journal_policy::exchange_digest(begin)?,
    ))
    .map_err(|_| HostError::StateInvalid)?;
    Ok(crate::host_crypto::digest(&wire)
        .trim_start_matches("sha256:")
        .to_owned())
}

pub(crate) fn command(
    value: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> Result<&'static str, HostError> {
    match &value.request.command {
        ihat_identity_assertion_contracts::AuthorityCommand::RevokeDeviceByRef(_) => {
            Ok("revoke_device_by_ref")
        }
        ihat_identity_assertion_contracts::AuthorityCommand::RevokeSessionByRef(_) => {
            Ok("revoke_session_by_ref")
        }
        _ => Err(HostError::EvidenceInvalid),
    }
}
