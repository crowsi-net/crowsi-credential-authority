use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointFreshUvTrustV2, EndpointIdentityTrustV2,
    EndpointPreparedOperationV2, ManagementCommandV2, SignedAuthorityExchangeV1,
    SignedTargetDeviceProofV2, WebAuthnOptionsV2, verify_authority_exchange_at,
    verify_endpoint_approval_at, verify_target_device_proof_at,
};
use ihat_identity_assertion_contracts::{
    AuthorityResult, FreshUvV1, IdentityEvidenceMetadata, ResponseOutcome,
};

use crate::{HostError, host_config::VerifiedHostConfig, host_config_types::HostOwnerMapping};

pub(crate) use crate::management_v2_evidence_ceremony::{
    independent_pre_final_ceremony, source_ceremony,
};

pub(crate) struct VerifiedManagementApproval {
    pub fresh_uv: FreshUvV1,
    pub session_sender_key_id: String,
}

pub(crate) fn options(
    config: &VerifiedHostConfig,
    value: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<WebAuthnOptionsV2, HostError> {
    verify_exchange(config, value, "begin_fresh_user_verification", now)?;
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(value),
    } = &value.response.outcome
    else {
        return Err(HostError::EvidenceInvalid);
    };
    Ok(WebAuthnOptionsV2 {
        attempt_id: value.attempt_id.clone(),
        challenge: value.challenge.clone(),
        rp_id: value.rp_id.clone(),
        origin: value.origin.clone(),
        credential_id: value.credential_id.clone(),
        timeout_ms: value.timeout_ms,
        expires_at_epoch_s: value.expires_at_epoch_s,
        command_binding_sha256: value.command_binding_sha256.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn approval(
    config: &VerifiedHostConfig,
    owner: &HostOwnerMapping,
    selected_identity: &SignedAuthorityExchangeV1,
    begin: &SignedAuthorityExchangeV1,
    finish: &SignedAuthorityExchangeV1,
    current_identity: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    command: &ManagementCommandV2,
    now: u64,
) -> Result<VerifiedManagementApproval, HostError> {
    let value = verify_endpoint_approval_at(
        selected_identity,
        begin,
        finish,
        current_identity,
        prepared,
        command,
        &EndpointAuthorityResponseTrustV2 {
            minimum_config_generation: config.document.minimum_identity_config_generation,
            key_id: &config.document.identity_response_key_id,
            public_key_hex: &config.document.identity_response_public_key_hex,
        },
        &EndpointIdentityTrustV2 {
            issuer: &config.document.identity_issuer,
            audience: &config.document.management_audience,
            assertion_key_id: &config.document.identity_key_id,
            assertion_public_key_hex: &config.document.identity_public_key_hex,
            current_status_key_id: &config.document.current_status_key_id,
            current_status_public_key_hex: &config.document.current_status_public_key_hex,
            now_epoch_s: now,
        },
        &EndpointFreshUvTrustV2 {
            account_binding_sha256: &owner.account_binding_sha256,
            key_id: &config.document.user_verification_key_id,
            public_key_hex: &config.document.user_verification_public_key_hex,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::EvidenceInvalid)?;
    Ok(VerifiedManagementApproval {
        fresh_uv: value.fresh_uv.clone(),
        session_sender_key_id: value.current_session_sender_key_id.into(),
    })
}

pub(crate) fn target(
    config: &VerifiedHostConfig,
    identity: &IdentityEvidenceMetadata,
    owner: &HostOwnerMapping,
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    value: &SignedTargetDeviceProofV2,
    now: u64,
) -> Result<(), HostError> {
    let key = config
        .document
        .device_proof_keys
        .iter()
        .find(|item| {
            item.opaque_owner_ref == owner.opaque_owner_ref
                && item.device_id == identity.assertion.device_id
                && item.device_proof_key_ref == value.binding.device_proof_key_ref
        })
        .ok_or(HostError::EvidenceInvalid)?;
    if key.custody_revision != value.binding.custody_revision
        || key.device_proof_key_ref != identity.assertion.device_proof_key_ref
    {
        return Err(HostError::EvidenceInvalid);
    }
    verify_target_device_proof_at(
        identity,
        prepared,
        fresh,
        value,
        &key.device_proof_key_ref,
        &key.public_key_hex,
        now,
    )
    .map_err(|_| HostError::EvidenceInvalid)
}

pub(crate) fn verify_exchange(
    config: &VerifiedHostConfig,
    value: &SignedAuthorityExchangeV1,
    command: &str,
    now: u64,
) -> Result<(), HostError> {
    verify_authority_exchange_at(
        value,
        command,
        config.document.minimum_identity_config_generation,
        &config.document.identity_response_key_id,
        &config.document.identity_response_public_key_hex,
        now,
    )
    .map_err(|_| HostError::EvidenceInvalid)
}
