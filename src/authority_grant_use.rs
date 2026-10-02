use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, DeviceGrant, GrantId, GrantState, GrantUse,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn grants_for(&self, id: &crate::CredentialId) -> Vec<DeviceGrant> {
        self.store
            .read(|snapshot| {
                Ok(snapshot
                    .grants
                    .values()
                    .filter(|grant| &grant.credential_id == id)
                    .cloned()
                    .collect())
            })
            .unwrap_or_default()
    }

    pub fn grant_state(&self, id: &GrantId) -> Option<GrantState> {
        let now = self.now_ms().ok()?;
        self.store
            .transact(|snapshot| {
                let grant = snapshot
                    .grants
                    .get_mut(id)
                    .ok_or(AuthorityError::NotFound)?;
                if grant.state == GrantState::Active && now > grant.expires_at_ms {
                    grant.state = GrantState::Expired;
                }
                Ok(grant.state)
            })
            .ok()
    }

    pub fn authorize_grant_use(&mut self, request: GrantUse) -> Result<(), AuthorityError> {
        let now = self.now_ms()?;
        self.store.transact(|snapshot| {
            let observed = snapshot
                .grants
                .get(&request.grant_id)
                .ok_or(AuthorityError::NotFound)?
                .clone();
            if observed.owner != request.owner {
                return Ok(Err(AuthorityError::WrongOwner));
            }
            if observed.target_device != request.device {
                return Ok(Err(AuthorityError::WrongDevice));
            }
            if observed.audience != request.audience {
                return Ok(Err(AuthorityError::WrongAudience));
            }
            if observed.action != request.action {
                return Ok(Err(AuthorityError::WrongAction));
            }
            let current_source = snapshot
                .devices
                .get(&(observed.owner.clone(), observed.source_device.clone()))
                .ok_or(AuthorityError::WrongDevice)?
                .clone();
            let current_target = snapshot
                .devices
                .get(&(request.owner.clone(), request.device.clone()))
                .ok_or(AuthorityError::WrongDevice)?
                .clone();
            let credential = snapshot
                .credentials
                .get(&observed.credential_id)
                .ok_or(AuthorityError::NotFound)?;
            let grant = snapshot
                .grants
                .get_mut(&request.grant_id)
                .ok_or(AuthorityError::NotFound)?;
            if credential.revoked || grant.credential_revision != credential.revision {
                return Ok(Err(AuthorityError::AccountUnavailable));
            }
            if request.epoch != current_target.epoch
                || grant.target_epoch != current_target.epoch
                || grant.source_epoch != current_source.epoch
                || grant.subject_revocation_epoch != current_source.subject_revocation_epoch
                || grant.service_revocation_epoch != current_source.service_revocation_epoch
                || grant.session_revocation_epoch != current_source.session_revocation_epoch
            {
                return Ok(Err(AuthorityError::StaleRevocationEpoch));
            }
            if grant.pairwise_subject_ref != current_source.pairwise_subject_ref
                || grant.identity_issuer != current_source.issuer
                || grant.identity_service_id != current_source.service_id
                || grant.source_key_thumbprint != current_source.key_thumbprint
                || grant.target_key_thumbprint != current_target.key_thumbprint
                || grant.source_posture_revision != current_source.posture_revision
                || grant.target_posture_revision != current_target.posture_revision
                || grant.source_posture_state != current_source.posture_state
                || grant.identity_key_id != current_source.key_id
            {
                return Ok(Err(AuthorityError::IdentityAssertionInvalid));
            }
            if grant.state == GrantState::Consumed {
                return Ok(Err(AuthorityError::GrantAlreadyConsumed));
            }
            if grant.state == GrantState::Expired || now > grant.expires_at_ms {
                grant.state = GrantState::Expired;
                return Ok(Err(AuthorityError::GrantExpired));
            }
            if grant.state != GrantState::Active {
                return Ok(Err(AuthorityError::AccountUnavailable));
            }
            grant.state = GrantState::Consumed;
            Ok(Ok(()))
        })?
    }
}
