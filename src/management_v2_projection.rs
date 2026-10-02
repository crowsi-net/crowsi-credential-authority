use crowsi_credential_authority_contracts::{
    MANAGEMENT_PROJECTION_SCHEMA, ManagementProjectionBodyV2, ManagementProjectionV2,
    ManagementRequestV2, canonical_management_projection, management_command_digest,
};
use ihat_identity_assertion_contracts::IdentityEvidenceMetadata;

use crate::{HostError, host_config::VerifiedHostConfig, host_crypto};

pub(crate) fn signed(
    config: &VerifiedHostConfig,
    request: &ManagementRequestV2,
    identity: &IdentityEvidenceMetadata,
    owner: &str,
    snapshot_revision: u64,
    body: ManagementProjectionBodyV2,
    now: u64,
) -> Result<Vec<u8>, HostError> {
    let command_digest =
        management_command_digest(request).map_err(|_| HostError::RequestInvalid)?;
    signed_bound(
        config,
        &request.request_id,
        command_digest,
        identity,
        owner,
        snapshot_revision,
        body,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn signed_bound(
    config: &VerifiedHostConfig,
    request_id: &str,
    command_digest: String,
    identity: &IdentityEvidenceMetadata,
    owner: &str,
    snapshot_revision: u64,
    body: ManagementProjectionBodyV2,
    now: u64,
) -> Result<Vec<u8>, HostError> {
    let projection_seed = [
        request_id.as_bytes(),
        command_digest.as_bytes(),
        identity.assertion.nonce.as_bytes(),
        &snapshot_revision.to_be_bytes(),
    ]
    .concat();
    let projection_digest = host_crypto::digest(&projection_seed);
    let epochs = &identity.assertion.revocation_epochs;
    let mut value = ManagementProjectionV2 {
        schema: MANAGEMENT_PROJECTION_SCHEMA.into(),
        projection_id: format!(
            "projection_{}",
            projection_digest.trim_start_matches("sha256:")
        ),
        request_id: request_id.into(),
        command_digest_sha256: command_digest,
        issuer: config.document.management_projection_issuer.clone(),
        audience: config.document.management_audience.clone(),
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        opaque_account_ref: owner.into(),
        current_device_ref: identity.assertion.device_id.clone(),
        current_session_ref: identity.assertion.session_ref.clone(),
        subject_revocation_epoch: epochs.subject,
        service_revocation_epoch: epochs.service,
        device_revocation_epoch: epochs.device,
        session_revocation_epoch: epochs.session,
        device_posture_state: identity.assertion.device_posture.state.clone(),
        device_posture_revision: identity.assertion.device_posture.revision,
        device_proof_key_ref: identity.assertion.device_proof_key_ref.clone(),
        snapshot_revision,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(30),
        body,
        key_id: config.document.management_projection_key_id.clone(),
        signature: String::new(),
    };
    let canonical =
        canonical_management_projection(&value).map_err(|_| HostError::ResponseInvalid)?;
    value.signature = host_crypto::sign(&config.management_projection_signing_key, &canonical);
    let wire = serde_json::to_vec(&value).map_err(|_| HostError::ResponseInvalid)?;
    if wire.len() <= 262_144 {
        Ok(wire)
    } else {
        Err(HostError::ResponseInvalid)
    }
}
