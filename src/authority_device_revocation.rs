use crate::state::DeviceRecord;
use crate::validation::{active_account, step_up};
use crate::{
    AuthorityError, AuthorityStore, CoelaDeviceRevocationRequest, CredentialAuthority,
    DeviceIdentityBinding, DeviceRevocationReceipt, GrantState,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub(crate) fn revoke_device_from_identity(
        &mut self,
        request: CoelaDeviceRevocationRequest,
        binding: &DeviceIdentityBinding,
    ) -> Result<DeviceRevocationReceipt, AuthorityError> {
        let now = self.now_ms()?;
        self.store.transact(|snapshot| {
            active_account(snapshot, &request.owner)?;
            step_up(
                snapshot,
                &request.owner,
                &binding.device_id,
                &request.step_up,
                now,
            )?;
            let source = snapshot
                .devices
                .get(&(request.owner.clone(), binding.device_id.clone()))
                .ok_or(AuthorityError::IdentityAssertionInvalid)?;
            if !matches_binding(source, binding) {
                return Err(AuthorityError::IdentityAssertionInvalid);
            }
            let nonce = format!("identity:{}", binding.nonce);
            if !snapshot.used_nonces.insert(nonce) {
                return Err(AuthorityError::IdentityAssertionReplay);
            }
            let record = snapshot
                .devices
                .get_mut(&(request.owner.clone(), request.target_device.clone()))
                .ok_or(AuthorityError::WrongDevice)?;
            if record.epoch != request.expected_device_epoch {
                return Err(AuthorityError::StaleRevocationEpoch);
            }
            let previous = record.epoch;
            record.epoch = record
                .epoch
                .checked_add(1)
                .ok_or(AuthorityError::InvalidValue("revocation epoch"))?;
            record.revoked = true;
            for session in snapshot.sessions.values_mut() {
                if session.owner == request.owner
                    && session.device_id == request.target_device
                    && !session.revoked
                {
                    session.revoked = true;
                    session.epoch = session.epoch.saturating_add(1);
                }
            }
            for grant in snapshot.grants.values_mut() {
                if grant.owner == request.owner
                    && (grant.source_device == request.target_device
                        || grant.target_device == request.target_device)
                    && matches!(grant.state, GrantState::Active | GrantState::Pending)
                {
                    grant.state = GrantState::Revoked;
                }
            }
            Ok(DeviceRevocationReceipt {
                previous,
                current: record.epoch,
            })
        })
    }
}

fn matches_binding(record: &DeviceRecord, binding: &DeviceIdentityBinding) -> bool {
    !record.revoked
        && record.key_thumbprint == binding.device_proof_key_ref
        && record.issuer == binding.issuer
        && record.service_id == binding.service_id
        && record.posture_state == binding.posture_state
        && record.posture_revision == binding.posture_revision
        && record.epoch == binding.device_revocation_epoch
        && record.subject_revocation_epoch == binding.subject_revocation_epoch
        && record.service_revocation_epoch == binding.service_revocation_epoch
        && record.session_revocation_epoch == binding.session_revocation_epoch
        && record.key_id == binding.key_id
        && record.pairwise_subject_ref == binding.pairwise_subject
}
