use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, DeviceIdentityBinding, GrantAudience,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub(crate) fn validate_identity_binding(
        &self,
        binding: &DeviceIdentityBinding,
        audience: &GrantAudience,
    ) -> Result<(), AuthorityError> {
        let now = self.now_ms()? / 1_000;
        let bounded = binding.pairwise_subject.starts_with("psu_")
            && binding.pairwise_subject.len() <= 128
            && !binding.issuer.is_empty()
            && binding.issuer.len() <= 256
            && !binding.device_proof_key_ref.is_empty()
            && binding.device_proof_key_ref.len() <= 256
            && !binding.posture_state.is_empty()
            && binding.posture_state.len() <= 32
            && binding.posture_revision > 0
            && binding.subject_revocation_epoch > 0
            && binding.service_revocation_epoch > 0
            && binding.device_revocation_epoch > 0
            && binding.session_revocation_epoch > 0
            && !binding.nonce.is_empty()
            && binding.nonce.len() <= 128
            && !binding.key_id.is_empty()
            && binding.key_id.len() <= 128
            && binding.issued_at_epoch_s <= now
            && binding.expires_at_epoch_s >= now;
        if !bounded || &binding.audience != audience {
            return Err(AuthorityError::IdentityAssertionInvalid);
        }
        Ok(())
    }

    pub(crate) fn validate_registered_identity(
        &self,
        owner: &crate::OpaqueOwnerRef,
        binding: &DeviceIdentityBinding,
    ) -> Result<(), AuthorityError> {
        self.store.read(|snapshot| {
            let device = snapshot
                .devices
                .get(&(owner.clone(), binding.device_id.clone()))
                .ok_or(AuthorityError::IdentityAssertionInvalid)?;
            let valid = device.key_thumbprint == binding.device_proof_key_ref
                && !device.revoked
                && device.issuer == binding.issuer
                && device.service_id == binding.service_id
                && device.posture_state == binding.posture_state
                && device.posture_revision == binding.posture_revision
                && device.epoch == binding.device_revocation_epoch
                && device.subject_revocation_epoch == binding.subject_revocation_epoch
                && device.service_revocation_epoch == binding.service_revocation_epoch
                && device.session_revocation_epoch == binding.session_revocation_epoch
                && device.key_id == binding.key_id
                && device.pairwise_subject_ref == binding.pairwise_subject;
            if valid {
                Ok(())
            } else {
                Err(AuthorityError::IdentityAssertionInvalid)
            }
        })
    }
}
