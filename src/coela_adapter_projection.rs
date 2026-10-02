use crate::identity::verify_device_identity_assertion;
#[cfg(feature = "test-support")]
use crate::session::SessionRecord;
use crate::{
    AuthorityError, AuthorityStore, CoelaAuthorityAdapter, CoelaManagementProjection,
    IdentityAssertionVerifier, OperationProofVerifier, ProviderEvidenceVerifier,
    ServiceAccountOwnerMapper,
};

impl<S, I, M, P> CoelaAuthorityAdapter<S, I, M, P>
where
    S: AuthorityStore,
    I: IdentityAssertionVerifier,
    M: ServiceAccountOwnerMapper,
    P: ProviderEvidenceVerifier + OperationProofVerifier,
{
    #[cfg(feature = "test-support")]
    pub fn list_account(
        &mut self,
        assertion: &[u8],
        limit: usize,
    ) -> Result<CoelaManagementProjection, AuthorityError> {
        if !(1..=100).contains(&limit) {
            return Err(AuthorityError::ProjectionLimitOutOfRange);
        }
        let binding = verify_device_identity_assertion(
            assertion,
            &self.management_audience,
            &self.identity_verifier,
            self.authority.now_ms()? / 1_000,
        )?;
        self.authority
            .validate_identity_binding(&binding, &self.management_audience)?;
        let owner = self.owner_mapper.map_owner(
            &binding.issuer,
            &binding.service_id,
            &binding.pairwise_subject,
        )?;
        self.authority
            .validate_registered_identity(&owner, &binding)?;
        let nonce = format!("identity:{}", binding.nonce);
        let now = self.authority.now_ms()?;
        self.authority.store.transact(|snapshot| {
            if !crate::authority_limits::identity_available(
                snapshot,
                &owner,
                &binding.device_id,
                &binding.session_ref,
            ) {
                return Err(AuthorityError::InvalidValue("owner identity capacity"));
            }
            if !snapshot.used_nonces.insert(nonce) {
                return Err(AuthorityError::IdentityAssertionReplay);
            }
            snapshot
                .devices
                .get_mut(&(owner.clone(), binding.device_id.clone()))
                .ok_or(AuthorityError::IdentityAssertionInvalid)?
                .last_seen_at_ms = now;
            snapshot.sessions.insert(
                (owner.clone(), binding.session_ref.clone()),
                SessionRecord {
                    owner: owner.clone(),
                    device_id: binding.device_id.clone(),
                    session_ref: binding.session_ref.clone(),
                    epoch: binding.session_revocation_epoch,
                    issued_at_ms: binding.issued_at_epoch_s.saturating_mul(1_000),
                    expires_at_ms: binding.expires_at_epoch_s.saturating_mul(1_000),
                    last_seen_at_ms: now,
                    revoked: false,
                },
            );
            Ok(())
        })?;
        self.authority.project_coela_management(&owner, limit)
    }

    pub(crate) fn list_account_passive(
        &self,
        assertion: &[u8],
        limit: usize,
    ) -> Result<CoelaManagementProjection, AuthorityError> {
        if !(1..=100).contains(&limit) {
            return Err(AuthorityError::ProjectionLimitOutOfRange);
        }
        let binding = verify_device_identity_assertion(
            assertion,
            &self.management_audience,
            &self.identity_verifier,
            self.authority.now_ms()? / 1_000,
        )?;
        self.authority
            .validate_identity_binding(&binding, &self.management_audience)?;
        let owner = self.owner_mapper.map_owner(
            &binding.issuer,
            &binding.service_id,
            &binding.pairwise_subject,
        )?;
        self.authority
            .validate_registered_identity(&owner, &binding)?;
        self.authority.project_coela_management(&owner, limit)
    }
}
