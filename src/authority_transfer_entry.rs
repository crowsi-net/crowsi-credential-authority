use crate::identity::verify_device_identity_assertion;
use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, GrantPairState, GrantState,
    IdentityAssertionVerifier, ServiceAccountOwnerMapper, TransferId, TransferReceipt,
    TransferRequest, TransferState,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn prepare_transfer_from_assertion<
        V: IdentityAssertionVerifier,
        M: ServiceAccountOwnerMapper,
    >(
        &mut self,
        request: TransferRequest,
        assertion_wire: &[u8],
        verifier: &V,
        mapper: &M,
    ) -> Result<TransferReceipt, AuthorityError> {
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
        self.validate_registered_identity(&owner, &binding)?;
        self.prepare_transfer_internal(request, format!("identity:{}", binding.nonce), None)
    }

    pub fn transfer_grant_states(&self, id: &TransferId) -> GrantPairState {
        self.store
            .read(|snapshot| {
                let transfer = snapshot.transfers.get(id).ok_or(AuthorityError::NotFound)?;
                let source = snapshot
                    .grants
                    .get(&transfer.source_grant)
                    .ok_or(AuthorityError::NotFound)?
                    .state;
                let target = snapshot
                    .grants
                    .get(&transfer.target_grant)
                    .ok_or(AuthorityError::NotFound)?
                    .state;
                Ok(GrantPairState { source, target })
            })
            .unwrap_or(GrantPairState {
                source: GrantState::Revoked,
                target: GrantState::Revoked,
            })
    }

    pub fn transfer_state(&self, id: &TransferId) -> Option<TransferState> {
        self.store
            .read(|snapshot| Ok(snapshot.transfers.get(id).map(|value| value.state)))
            .ok()
            .flatten()
    }
}
