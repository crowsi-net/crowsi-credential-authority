use crate::{
    AccountState, AuthorityError, AuthorityStore, CredentialAuthority, CredentialId,
    CredentialMetadata, CredentialRegistration, OpaqueOwnerRef,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn register_credential(
        &mut self,
        request: CredentialRegistration,
    ) -> Result<(), AuthorityError> {
        if request.alias.is_empty() || request.alias.len() > 128 || request.revision == 0 {
            return Err(AuthorityError::InvalidValue("credential metadata"));
        }
        let now_ms = self.now_ms()?;
        self.store.transact(|snapshot| {
            if snapshot.credentials.contains_key(&request.id) {
                return Err(AuthorityError::CredentialAlreadyOwned);
            }
            if !crate::authority_limits::credential_available(snapshot, &request.owner) {
                return Err(AuthorityError::InvalidValue("owner credential capacity"));
            }
            snapshot
                .accounts
                .entry(request.owner.clone())
                .or_insert(AccountState::Active);
            snapshot.credentials.insert(
                request.id.clone(),
                CredentialMetadata::from_registration(request, now_ms),
            );
            Ok(())
        })
    }

    pub fn credential_metadata(
        &self,
        owner: &OpaqueOwnerRef,
        id: &CredentialId,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.store.read(|snapshot| {
            let value = snapshot
                .credentials
                .get(id)
                .ok_or(AuthorityError::NotFound)?;
            if &value.owner != owner {
                return Err(AuthorityError::WrongOwner);
            }
            if value.revoked {
                return Err(AuthorityError::AccountUnavailable);
            }
            Ok(value.clone())
        })
    }

    pub fn claim_existing_credential(
        &mut self,
        _owner: OpaqueOwnerRef,
        id: CredentialId,
        _service: crate::ServiceId,
        _provider_account: crate::ProviderAccountRef,
    ) -> Result<(), AuthorityError> {
        self.store.read(|snapshot| {
            if snapshot.credentials.contains_key(&id) {
                Err(AuthorityError::CredentialAlreadyOwned)
            } else {
                Err(AuthorityError::NotFound)
            }
        })
    }
}
