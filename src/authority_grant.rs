use crate::identity::verify_device_identity_assertion;
use crate::validation::{active_account, step_up, target_proof, ttl};
use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, DeviceGrant, DeviceGrantRequest, GrantId,
    GrantState, IdentityAssertionVerifier, ServiceAccountOwnerMapper,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn issue_device_grant_from_assertion<
        V: IdentityAssertionVerifier,
        M: ServiceAccountOwnerMapper,
    >(
        &mut self,
        request: DeviceGrantRequest,
        assertion_wire: &[u8],
        verifier: &V,
        mapper: &M,
    ) -> Result<DeviceGrant, AuthorityError> {
        let binding = verify_device_identity_assertion(
            assertion_wire,
            &request.audience,
            verifier,
            self.now_ms()? / 1_000,
        )?;
        self.validate_identity_binding(&binding, &request.audience)?;
        let owner = mapper.map_owner(
            &binding.issuer,
            &binding.service_id,
            &binding.pairwise_subject,
        )?;
        if owner != request.owner || binding.device_id != request.source_device {
            return Err(AuthorityError::IdentityAssertionInvalid);
        }
        let service_matches = self.store.read(|snapshot| {
            Ok(snapshot
                .credentials
                .get(&request.credential_id)
                .is_some_and(|credential| credential.service == binding.service_id))
        })?;
        if !service_matches {
            return Err(AuthorityError::IdentityAssertionInvalid);
        }
        let now = self.now_ms()?;
        if now.saturating_add(request.ttl_ms) / 1_000 > binding.expires_at_epoch_s {
            return Err(AuthorityError::IdentityAssertionInvalid);
        }
        let nonce = format!("identity:{}", binding.nonce);
        self.validate_registered_identity(&owner, &binding)?;
        self.issue_grant_internal(request, nonce)
    }

    pub(crate) fn issue_grant_internal(
        &self,
        request: DeviceGrantRequest,
        identity_nonce: String,
    ) -> Result<DeviceGrant, AuthorityError> {
        let now = self.now_ms()?;
        ttl(request.ttl_ms)?;
        self.store.transact(|snapshot| {
            crate::authority_grant_limits::expire(snapshot, now);
            let credential = snapshot
                .credentials
                .get(&request.credential_id)
                .ok_or(AuthorityError::NotFound)?
                .clone();
            if credential.owner != request.owner {
                return Err(AuthorityError::WrongOwner);
            }
            active_account(snapshot, &request.owner)?;
            if credential.revoked {
                return Err(AuthorityError::AccountUnavailable);
            }
            if !crate::authority_grant_limits::one_available(
                snapshot,
                &request.owner,
                &request.credential_id,
            ) {
                return Err(AuthorityError::InvalidValue(
                    "device credential grant capacity",
                ));
            }
            step_up(
                snapshot,
                &request.owner,
                &request.source_device,
                &request.step_up,
                now,
            )?;
            target_proof(
                snapshot,
                &request.owner,
                &request.target_device,
                &request.target_proof,
                now,
            )?;
            let source = snapshot
                .devices
                .get(&(request.owner.clone(), request.source_device.clone()))
                .ok_or(AuthorityError::WrongDevice)?
                .clone();
            let target = snapshot
                .devices
                .get(&(request.owner.clone(), request.target_device.clone()))
                .ok_or(AuthorityError::WrongDevice)?
                .clone();
            if !snapshot.used_nonces.insert(identity_nonce) {
                return Err(AuthorityError::IdentityAssertionReplay);
            }
            snapshot
                .used_nonces
                .insert(format!("target:{}", request.target_proof.nonce));
            let id = GrantId::trusted(format!("grant-{}", snapshot.next_sequence()));
            let grant = DeviceGrant {
                id: id.clone(),
                owner: request.owner,
                credential_id: request.credential_id,
                credential_revision: credential.revision,
                source_device: request.source_device,
                target_device: request.target_device,
                audience: request.audience,
                action: request.action,
                source_epoch: source.epoch,
                target_epoch: target.epoch,
                pairwise_subject_ref: source.pairwise_subject_ref,
                identity_issuer: source.issuer,
                identity_service_id: source.service_id,
                source_key_thumbprint: source.key_thumbprint,
                target_key_thumbprint: target.key_thumbprint,
                source_posture_revision: source.posture_revision,
                target_posture_revision: target.posture_revision,
                source_posture_state: source.posture_state,
                subject_revocation_epoch: source.subject_revocation_epoch,
                service_revocation_epoch: source.service_revocation_epoch,
                session_revocation_epoch: source.session_revocation_epoch,
                identity_key_id: source.key_id,
                expires_at_ms: now.saturating_add(request.ttl_ms),
                state: GrantState::Active,
            };
            snapshot.grants.insert(id, grant.clone());
            Ok(grant)
        })
    }
}
