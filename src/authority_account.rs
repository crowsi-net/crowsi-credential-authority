use crate::validation::{active_account, step_up};
use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, CredentialId, CredentialRevocationReceipt,
    DeviceId, DeviceRevocationReceipt, GrantState, OpaqueOwnerRef, RevocationCause, StepUpProof,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn revoke_device(
        &mut self,
        owner: &OpaqueOwnerRef,
        device: &DeviceId,
        _cause: RevocationCause,
        proof: StepUpProof,
    ) -> Result<DeviceRevocationReceipt, AuthorityError> {
        let now = self.now_ms()?;
        self.store.transact(|snapshot| {
            active_account(snapshot, owner)?;
            step_up(snapshot, owner, &proof.device, &proof, now)?;
            let record = snapshot
                .devices
                .get_mut(&(owner.clone(), device.clone()))
                .ok_or(AuthorityError::WrongDevice)?;
            let previous = record.epoch;
            record.epoch = record
                .epoch
                .checked_add(1)
                .ok_or(AuthorityError::InvalidValue("revocation epoch"))?;
            for grant in snapshot.grants.values_mut() {
                if &grant.owner == owner
                    && (&grant.source_device == device || &grant.target_device == device)
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

    pub fn device_epoch(&self, device: &DeviceId) -> Option<u64> {
        self.store
            .read(|snapshot| {
                Ok(snapshot.devices.iter().find_map(|((_, id), record)| {
                    if id == device {
                        Some(record.epoch)
                    } else {
                        None
                    }
                }))
            })
            .ok()
            .flatten()
    }

    pub fn revoke_credential(
        &mut self,
        owner: &OpaqueOwnerRef,
        id: &CredentialId,
        _cause: RevocationCause,
        proof: StepUpProof,
    ) -> Result<CredentialRevocationReceipt, AuthorityError> {
        let now = self.now_ms()?;
        self.store.transact(|snapshot| {
            active_account(snapshot, owner)?;
            step_up(snapshot, owner, &proof.device, &proof, now)?;
            let credential = snapshot
                .credentials
                .get_mut(id)
                .ok_or(AuthorityError::NotFound)?;
            if &credential.owner != owner {
                return Err(AuthorityError::WrongOwner);
            }
            credential.revoked = true;
            let mut revoked = 0;
            for grant in snapshot.grants.values_mut() {
                if &grant.credential_id == id
                    && matches!(grant.state, GrantState::Active | GrantState::Pending)
                {
                    grant.state = GrantState::Revoked;
                    revoked += 1;
                }
            }
            Ok(CredentialRevocationReceipt {
                revoked_grants: revoked,
            })
        })
    }

    pub fn revoke_credential_revision(
        &mut self,
        owner: &OpaqueOwnerRef,
        id: &CredentialId,
        revision: u64,
        _cause: RevocationCause,
    ) -> Result<CredentialRevocationReceipt, AuthorityError> {
        self.store.transact(|snapshot| {
            let credential = snapshot
                .credentials
                .get(id)
                .ok_or(AuthorityError::NotFound)?;
            if &credential.owner != owner {
                return Err(AuthorityError::WrongOwner);
            }
            let mut revoked = 0;
            for grant in snapshot.grants.values_mut() {
                if &grant.credential_id == id
                    && grant.credential_revision == revision
                    && matches!(grant.state, GrantState::Active | GrantState::Pending)
                {
                    grant.state = GrantState::Revoked;
                    revoked += 1;
                }
            }
            Ok(CredentialRevocationReceipt {
                revoked_grants: revoked,
            })
        })
    }
}
