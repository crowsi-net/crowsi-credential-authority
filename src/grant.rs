use crate::{
    CredentialId, DeviceId, GrantAction, GrantAudience, GrantId, OpaqueOwnerRef, StepUpProof,
    TargetKeyProof,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum GrantState {
    Active,
    Pending,
    Consumed,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceGrantRequest {
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) credential_id: CredentialId,
    pub(crate) source_device: DeviceId,
    pub(crate) target_device: DeviceId,
    pub(crate) audience: GrantAudience,
    pub(crate) action: GrantAction,
    pub(crate) ttl_ms: u64,
    pub(crate) step_up: StepUpProof,
    pub(crate) target_proof: TargetKeyProof,
}

impl DeviceGrantRequest {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        owner: OpaqueOwnerRef,
        credential_id: CredentialId,
        source_device: DeviceId,
        target_device: DeviceId,
        audience: GrantAudience,
        action: GrantAction,
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
            ttl_ms,
            step_up,
            target_proof,
        }
    }

    pub fn with_owner(mut self, owner: OpaqueOwnerRef) -> Self {
        self.owner = owner;
        self
    }
    pub fn with_step_up(mut self, proof: StepUpProof) -> Self {
        self.step_up = proof;
        self
    }
    pub fn with_target_key_proof(mut self, proof: TargetKeyProof) -> Self {
        self.target_proof = proof;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceGrant {
    pub(crate) id: GrantId,
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) credential_id: CredentialId,
    pub(crate) credential_revision: u64,
    pub(crate) source_device: DeviceId,
    pub(crate) target_device: DeviceId,
    pub(crate) audience: GrantAudience,
    pub(crate) action: GrantAction,
    pub(crate) source_epoch: u64,
    pub(crate) target_epoch: u64,
    pub(crate) pairwise_subject_ref: String,
    pub(crate) identity_issuer: String,
    pub(crate) identity_service_id: crate::ServiceId,
    pub(crate) source_key_thumbprint: String,
    pub(crate) target_key_thumbprint: String,
    pub(crate) source_posture_revision: u64,
    pub(crate) target_posture_revision: u64,
    pub(crate) source_posture_state: String,
    pub(crate) subject_revocation_epoch: u64,
    pub(crate) service_revocation_epoch: u64,
    pub(crate) session_revocation_epoch: u64,
    pub(crate) identity_key_id: String,
    pub(crate) expires_at_ms: u64,
    pub(crate) state: GrantState,
}

impl DeviceGrant {
    pub fn id(&self) -> &GrantId {
        &self.id
    }
    pub fn owner(&self) -> &OpaqueOwnerRef {
        &self.owner
    }
    pub fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }
    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }
    pub fn source_device(&self) -> &DeviceId {
        &self.source_device
    }
    pub fn target_device(&self) -> &DeviceId {
        &self.target_device
    }
    pub fn audience(&self) -> &GrantAudience {
        &self.audience
    }
    pub fn action(&self) -> &GrantAction {
        &self.action
    }
    pub const fn source_revocation_epoch(&self) -> u64 {
        self.source_epoch
    }
    pub const fn target_revocation_epoch(&self) -> u64 {
        self.target_epoch
    }
}
