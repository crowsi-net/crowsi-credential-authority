use ihat_identity_assertion_contracts::{AssertionVerifier, CurrentDeviceStatusV1};

use crate::{
    AuthorityError, DeviceIdentityBinding, IdentityAssertionVerifier, OpaqueOwnerRef,
    ServiceAccountOwnerMapper, ServiceId, host_config::VerifiedHostConfig, host_crypto,
};

#[derive(Clone)]
pub(crate) struct HostIdentityVerifier {
    issuer: String,
    key_id: String,
    public_key: String,
    status: CurrentDeviceStatusV1,
}

impl HostIdentityVerifier {
    pub(crate) fn new(config: &VerifiedHostConfig, status: CurrentDeviceStatusV1) -> Self {
        Self {
            issuer: config.document.identity_issuer.clone(),
            key_id: config.document.identity_key_id.clone(),
            public_key: config.document.identity_public_key_hex.clone(),
            status,
        }
    }
}

impl AssertionVerifier for HostIdentityVerifier {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        key_id == self.key_id && host_crypto::verify(&self.public_key, signature, payload)
    }
}

impl IdentityAssertionVerifier for HostIdentityVerifier {
    fn expected_issuer(&self) -> &str {
        &self.issuer
    }
    fn revocation_epochs_are_current(&self, value: &DeviceIdentityBinding) -> bool {
        value.device_id.as_str() == self.status.device_id
            && value.device_proof_key_ref == self.status.device_proof_key_ref
            && value.session_ref == self.status.session_ref
            && value.posture_state == self.status.device_posture.state
            && value.posture_revision == self.status.device_posture.revision
            && value.subject_revocation_epoch == self.status.revocation_epochs.subject
            && value.service_revocation_epoch == self.status.revocation_epochs.service
            && value.device_revocation_epoch == self.status.revocation_epochs.device
            && value.session_revocation_epoch == self.status.revocation_epochs.session
    }
}

#[derive(Clone)]
pub(crate) struct HostOwnerMapper(pub(crate) Vec<crate::host_config_types::HostOwnerMapping>);
impl ServiceAccountOwnerMapper for HostOwnerMapper {
    fn map_owner(
        &self,
        issuer: &str,
        service: &ServiceId,
        pairwise: &str,
    ) -> Result<OpaqueOwnerRef, AuthorityError> {
        let value = self
            .0
            .iter()
            .find(|item| {
                item.issuer == issuer
                    && item.service_id == service.as_str()
                    && item.pairwise_subject == pairwise
            })
            .ok_or(AuthorityError::WrongOwner)?;
        OpaqueOwnerRef::parse(value.opaque_owner_ref.clone())
    }
}
