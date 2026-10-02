use crate::identity::verify_device_identity_assertion;
use crate::session::SessionRecord;
use crate::state::DeviceRecord;
use crate::{
    AccountState, AuthorityError, AuthorityStore, CredentialAuthority, GrantAudience,
    IdentityAssertionVerifier, ServiceAccountOwnerMapper,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn register_device_from_assertion<
        V: IdentityAssertionVerifier,
        M: ServiceAccountOwnerMapper,
    >(
        &mut self,
        assertion_wire: &[u8],
        expected_audience: &GrantAudience,
        verifier: &V,
        mapper: &M,
    ) -> Result<(), AuthorityError> {
        let binding = verify_device_identity_assertion(
            assertion_wire,
            expected_audience,
            verifier,
            self.now_ms()? / 1_000,
        )?;
        self.validate_identity_binding(&binding, expected_audience)?;
        let owner = mapper.map_owner(
            &binding.issuer,
            &binding.service_id,
            &binding.pairwise_subject,
        )?;
        let now = self.now_ms()?;
        let nonce_key = format!("identity:{}", binding.nonce);
        let mut record = DeviceRecord {
            owner: owner.clone(),
            key_thumbprint: binding.device_proof_key_ref,
            epoch: binding.device_revocation_epoch,
            pairwise_subject_ref: binding.pairwise_subject,
            issuer: binding.issuer,
            service_id: binding.service_id,
            posture_state: binding.posture_state,
            posture_revision: binding.posture_revision,
            subject_revocation_epoch: binding.subject_revocation_epoch,
            service_revocation_epoch: binding.service_revocation_epoch,
            session_revocation_epoch: binding.session_revocation_epoch,
            key_id: binding.key_id,
            enrolled_at_ms: now,
            last_seen_at_ms: now,
            revoked: false,
        };
        self.store.transact(|snapshot| {
            if !crate::authority_limits::identity_available(
                snapshot,
                &owner,
                &binding.device_id,
                &binding.session_ref,
            ) {
                return Err(AuthorityError::InvalidValue("owner identity capacity"));
            }
            if !snapshot.used_nonces.insert(nonce_key) {
                return Err(AuthorityError::IdentityAssertionReplay);
            }
            if let Some(existing) = snapshot
                .devices
                .get(&(owner.clone(), binding.device_id.clone()))
            {
                let rolls_back = record.posture_revision < existing.posture_revision
                    || record.subject_revocation_epoch < existing.subject_revocation_epoch
                    || record.service_revocation_epoch < existing.service_revocation_epoch
                    || record.epoch < existing.epoch
                    || record.session_revocation_epoch < existing.session_revocation_epoch;
                let unversioned_key_change = record.key_thumbprint != existing.key_thumbprint
                    && record.epoch <= existing.epoch;
                if rolls_back || unversioned_key_change {
                    return Err(AuthorityError::StaleRevocationEpoch);
                }
                if existing.revoked {
                    return Err(AuthorityError::AccountUnavailable);
                }
                record.enrolled_at_ms = existing.enrolled_at_ms;
            }
            snapshot
                .accounts
                .entry(owner.clone())
                .or_insert(AccountState::Active);
            let device_id = binding.device_id.clone();
            snapshot
                .devices
                .insert((owner.clone(), device_id.clone()), record);
            snapshot.sessions.insert(
                (owner.clone(), binding.session_ref.clone()),
                SessionRecord {
                    owner,
                    device_id,
                    session_ref: binding.session_ref,
                    epoch: binding.session_revocation_epoch,
                    issued_at_ms: binding.issued_at_epoch_s.saturating_mul(1_000),
                    expires_at_ms: binding.expires_at_epoch_s.saturating_mul(1_000),
                    last_seen_at_ms: now,
                    revoked: false,
                },
            );
            Ok(())
        })
    }
}
