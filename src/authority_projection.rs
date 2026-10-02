use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, MetadataProjection,
    MetadataProjectionQuery,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn project_metadata(
        &self,
        query: MetadataProjectionQuery,
    ) -> Result<MetadataProjection, AuthorityError> {
        if !(1..=100).contains(&query.limit) {
            return Err(AuthorityError::ProjectionLimitOutOfRange);
        }
        self.store.read(|snapshot| {
            if !snapshot.accounts.contains_key(&query.owner) {
                return Err(AuthorityError::WrongOwner);
            }
            let credentials = snapshot
                .credentials
                .values()
                .filter(|credential| credential.owner == query.owner)
                .take(query.limit)
                .map(|credential| {
                    serde_json::json!({
                        "credential_id": credential.id.as_str(),
                        "owner_ref": credential.owner.as_str(),
                        "service_id": credential.service.as_str(),
                        "provider_account_ref": credential.provider_account.as_str(),
                        "alias": credential.alias,
                        "class": format!("{:?}", credential.class),
                        "revision": credential.revision,
                        "revoked": credential.revoked,
                    })
                })
                .collect::<Vec<_>>();
            let grants = snapshot
                .grants
                .values()
                .filter(|grant| grant.owner == query.owner)
                .take(query.limit)
                .map(|grant| {
                    serde_json::json!({
                        "grant_id": grant.id.as_str(),
                        "credential_id": grant.credential_id.as_str(),
                        "device_id": grant.target_device.as_str(),
                        "grant_state": format!("{:?}", grant.state),
                        "credential_revision": grant.credential_revision,
                        "revocation_epoch": grant.target_epoch,
                        "audience": grant.audience.as_str(),
                        "action": grant.action.as_str(),
                    })
                })
                .collect::<Vec<_>>();
            MetadataProjection::from_value(&serde_json::json!({
                "schema_id": "crowsi-credential-metadata-projection-v1",
                "credentials": credentials,
                "device_grants": grants,
            }))
        })
    }
}
