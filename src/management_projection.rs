use crate::{AccountState, AuthorityError, AuthorityStore, CredentialAuthority, OpaqueOwnerRef};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoelaManagementProjection {
    encoded: String,
}

impl CoelaManagementProjection {
    #[must_use]
    pub const fn contains_secret_values(&self) -> bool {
        false
    }

    pub fn encode_json(&self) -> Result<String, AuthorityError> {
        Ok(self.encoded.clone())
    }
}

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub(crate) fn project_coela_management(
        &self,
        owner: &OpaqueOwnerRef,
        limit: usize,
    ) -> Result<CoelaManagementProjection, AuthorityError> {
        if !(1..=100).contains(&limit) {
            return Err(AuthorityError::ProjectionLimitOutOfRange);
        }
        self.store.read(|snapshot| {
            if snapshot.accounts.get(owner) != Some(&AccountState::Active) {
                return Err(AuthorityError::AccountUnavailable);
            }
            if !crate::authority_limits::projection_complete(snapshot, owner) {
                return Err(AuthorityError::ProjectionLimitOutOfRange);
            }
            let credentials =
                crate::management_projection_records::credentials(snapshot, owner, limit);
            let devices = crate::management_projection_records::devices(snapshot, owner, limit);
            let sessions = crate::management_projection_records::sessions(snapshot, owner, limit);
            let revocation_epoch = snapshot
                .devices
                .iter()
                .filter(|((record_owner, _), _)| record_owner == owner)
                .map(|(_, value)| value.subject_revocation_epoch)
                .max()
                .unwrap_or(0);
            let value = serde_json::json!({
                "credentials": credentials,
                "devices": devices,
                "sessions": sessions,
                "revocation_epoch": revocation_epoch,
                "schema_id": "crowsi-coela-management-projection-v1",
            });
            let encoded =
                serde_json::to_string(&value).map_err(|_| AuthorityError::StoreUnavailable)?;
            if encoded.len() > 262_144 {
                return Err(AuthorityError::ProjectionLimitOutOfRange);
            }
            Ok(CoelaManagementProjection { encoded })
        })
    }
}
