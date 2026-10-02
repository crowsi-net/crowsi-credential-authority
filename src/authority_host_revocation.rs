use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, DeviceId, DeviceRevocationReceipt,
    GrantState, OpaqueOwnerRef,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub(crate) fn apply_host_device_revocation(
        &mut self,
        operation_id: &str,
        owner: &OpaqueOwnerRef,
        target: &DeviceId,
        previous: u64,
        current: u64,
    ) -> Result<DeviceRevocationReceipt, AuthorityError> {
        exact_generation(operation_id, previous, current)?;
        let replay = replay("device", operation_id, owner.as_str(), target.as_str());
        self.store.transact(|snapshot| {
            crate::validation::active_account(snapshot, owner)?;
            if snapshot.used_nonces.contains(&replay) {
                return exact_device(snapshot, owner, target, previous, current);
            }
            let device = snapshot
                .devices
                .get(&(owner.clone(), target.clone()))
                .ok_or(AuthorityError::WrongDevice)?;
            if device.revoked || device.epoch != previous {
                return Err(AuthorityError::StaleRevocationEpoch);
            }
            let device = snapshot
                .devices
                .get_mut(&(owner.clone(), target.clone()))
                .ok_or(AuthorityError::WrongDevice)?;
            device.revoked = true;
            device.epoch = current;
            for session in snapshot.sessions.values_mut() {
                if session.owner == *owner && session.device_id == *target && !session.revoked {
                    session.revoked = true;
                    session.epoch = session
                        .epoch
                        .checked_add(1)
                        .ok_or(AuthorityError::InvalidValue("session epoch"))?;
                }
            }
            for grant in snapshot.grants.values_mut() {
                if grant.owner == *owner
                    && (grant.source_device == *target || grant.target_device == *target)
                    && matches!(grant.state, GrantState::Active | GrantState::Pending)
                {
                    grant.state = GrantState::Revoked;
                }
            }
            snapshot.used_nonces.insert(replay);
            Ok(DeviceRevocationReceipt { previous, current })
        })
    }

    pub(crate) fn apply_host_session_revocation(
        &mut self,
        operation_id: &str,
        owner: &OpaqueOwnerRef,
        target_session: &str,
        previous: u64,
        current: u64,
    ) -> Result<(u64, u64), AuthorityError> {
        exact_generation(operation_id, previous, current)?;
        if target_session.is_empty() || target_session.len() > 128 {
            return Err(AuthorityError::InvalidValue("session ref"));
        }
        let replay = replay("session", operation_id, owner.as_str(), target_session);
        self.store.transact(|snapshot| {
            crate::validation::active_account(snapshot, owner)?;
            if snapshot.used_nonces.contains(&replay) {
                return exact_session(snapshot, owner, target_session, previous, current);
            }
            let session = snapshot
                .sessions
                .get_mut(&(owner.clone(), target_session.to_owned()))
                .ok_or(AuthorityError::NotFound)?;
            if session.revoked || session.epoch != previous {
                return Err(AuthorityError::StaleRevocationEpoch);
            }
            session.revoked = true;
            session.epoch = current;
            snapshot.used_nonces.insert(replay);
            Ok((previous, current))
        })
    }
}

fn exact_device(
    snapshot: &crate::state::DurableSnapshot,
    owner: &OpaqueOwnerRef,
    target: &DeviceId,
    previous: u64,
    current: u64,
) -> Result<DeviceRevocationReceipt, AuthorityError> {
    let applied = snapshot
        .devices
        .get(&(owner.clone(), target.clone()))
        .is_some_and(|value| value.revoked && value.epoch == current)
        && snapshot
            .sessions
            .values()
            .all(|value| value.owner != *owner || value.device_id != *target || value.revoked)
        && snapshot.grants.values().all(|value| {
            value.owner != *owner
                || (value.source_device != *target && value.target_device != *target)
                || !matches!(value.state, GrantState::Active | GrantState::Pending)
        });
    applied
        .then_some(DeviceRevocationReceipt { previous, current })
        .ok_or(AuthorityError::IntegrityViolation)
}

fn exact_session(
    snapshot: &crate::state::DurableSnapshot,
    owner: &OpaqueOwnerRef,
    target: &str,
    previous: u64,
    current: u64,
) -> Result<(u64, u64), AuthorityError> {
    snapshot
        .sessions
        .get(&(owner.clone(), target.to_owned()))
        .is_some_and(|value| value.revoked && value.epoch == current)
        .then_some((previous, current))
        .ok_or(AuthorityError::IntegrityViolation)
}

fn exact_generation(operation: &str, previous: u64, current: u64) -> Result<(), AuthorityError> {
    let operation_valid = operation.len() == 64
        && operation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    (operation_valid && previous.checked_add(1) == Some(current))
        .then_some(())
        .ok_or(AuthorityError::InvalidValue("host revocation"))
}

fn replay(kind: &str, operation: &str, owner: &str, target: &str) -> String {
    format!("host-revoke:{kind}:{operation}:{owner}:{target}")
}
