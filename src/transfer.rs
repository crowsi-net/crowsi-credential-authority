use crate::{
    CredentialId, DeviceId, GrantAction, GrantAudience, OpaqueOwnerRef, StepUpProof, TargetKeyProof,
};

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum TransferMechanism {
    ProviderReissue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum TransferState {
    Prepared,
    Committed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitFailPoint {
    BeforeSourceRevoke,
    AfterSourceRevokeBeforeTargetActivate,
    BeforeReceiptPersist,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRequest {
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) credential_id: CredentialId,
    pub(crate) source_device: DeviceId,
    pub(crate) target_device: DeviceId,
    pub(crate) audience: GrantAudience,
    pub(crate) action: GrantAction,
    pub(crate) mechanism: TransferMechanism,
    pub(crate) ttl_ms: u64,
    pub(crate) step_up: StepUpProof,
    pub(crate) target_proof: TargetKeyProof,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagementDeviceBinding {
    pub(crate) issuer: String,
    pub(crate) service_id: crate::ServiceId,
    pub(crate) pairwise_subject: String,
    pub(crate) device_id: DeviceId,
    pub(crate) device_proof_key_ref: String,
    pub(crate) posture_state: String,
    pub(crate) posture_revision: u64,
    pub(crate) subject_revocation_epoch: u64,
    pub(crate) service_revocation_epoch: u64,
    pub(crate) device_revocation_epoch: u64,
    pub(crate) session_revocation_epoch: u64,
    pub(crate) identity_key_id: String,
}

impl ManagementDeviceBinding {
    pub(crate) fn from_assertion(
        value: &ihat_identity_assertion_contracts::DeviceIdentityAssertionV1,
    ) -> Result<Self, crate::AuthorityError> {
        Ok(Self {
            issuer: value.issuer.clone(),
            service_id: crate::ServiceId::parse(value.service_id.clone())?,
            pairwise_subject: value.pairwise_subject.clone(),
            device_id: crate::DeviceId::parse(value.device_id.clone())?,
            device_proof_key_ref: value.device_proof_key_ref.clone(),
            posture_state: value.device_posture.state.clone(),
            posture_revision: value.device_posture.revision,
            subject_revocation_epoch: value.revocation_epochs.subject,
            service_revocation_epoch: value.revocation_epochs.service,
            device_revocation_epoch: value.revocation_epochs.device,
            session_revocation_epoch: value.revocation_epochs.session,
            identity_key_id: value.key_id.clone(),
        })
    }
}

impl TransferRequest {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        owner: OpaqueOwnerRef,
        credential_id: CredentialId,
        source_device: DeviceId,
        target_device: DeviceId,
        audience: GrantAudience,
        action: GrantAction,
        mechanism: TransferMechanism,
        ttl_ms: u64,
        step_up: StepUpProof,
        target_proof: TargetKeyProof,
    ) -> Self {
        Self {
            owner,
            credential_id,
            source_device,
            target_device,
            audience,
            action,
            mechanism,
            ttl_ms,
            step_up,
            target_proof,
        }
    }
}
