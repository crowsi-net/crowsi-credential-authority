impl<S: AuthorityStore> CredentialAuthority<S> {
    pub(crate) fn management_rotation_target(
        &self,
        owner: &OpaqueOwnerRef,
        service: &ServiceId,
        credential: &CredentialId,
        compromised: &DeviceId,
        candidates: &[String],
    ) -> Result<(DeviceId, RevocationTargetBindingV1), AuthorityError> {
        let now = self.now_ms()?;
        self.store.read(|snapshot| {
            let metadata = snapshot
                .credentials
                .get(credential)
                .ok_or(AuthorityError::NotFound)?;
            let credential_exact =
                metadata.owner == *owner && metadata.service == *service && !metadata.revoked;
            if !credential_exact {
                return Err(AuthorityError::IdentityAssertionInvalid);
            }
            let grants = grant_bindings(snapshot, owner, credential, compromised, now);
            if grants.is_empty() {
                return Err(AuthorityError::NotFound);
            }
            candidates
                .iter()
                .filter_map(|item| DeviceId::parse(item.clone()).ok())
                .filter(|item| item != compromised)
                .find_map(|target| {
                    let device = snapshot.devices.get(&(owner.clone(), target.clone()))?;
                    (device.owner == *owner && device.service_id == *service && !device.revoked)
                        .then(|| (target, binding(metadata.revision, device, grants.clone())))
                })
                .ok_or(AuthorityError::WrongDevice)
        })
    }

    pub(crate) fn management_rotation_target_current(
        &self,
        owner: &OpaqueOwnerRef,
        service: &ServiceId,
        credential: &CredentialId,
        target: &DeviceId,
        compromised: &DeviceId,
        expected: &RevocationTargetBindingV1,
    ) -> Result<(), AuthorityError> {
        self.store.read(|snapshot| {
            let metadata = snapshot
                .credentials
                .get(credential)
                .ok_or(AuthorityError::NotFound)?;
            let device = snapshot
                .devices
                .get(&(owner.clone(), target.clone()))
                .ok_or(AuthorityError::WrongDevice)?;
            let exact = metadata.owner == *owner
                && metadata.service == *service
                && !metadata.revoked
                && target != compromised
                && device.owner == *owner
                && device.service_id == *service
                && !device.revoked
                && target_fields(metadata.revision, device, expected)
                && bound_grants_current(snapshot, owner, credential, compromised, expected);
            exact
                .then_some(())
                .ok_or(AuthorityError::IdentityAssertionInvalid)
        })
    }
}
