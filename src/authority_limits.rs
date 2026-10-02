#[cfg(feature = "test-support")]
use crate::DeviceId;
use crate::{DurableSnapshot, OpaqueOwnerRef};

pub(crate) const OWNER_CREDENTIALS: usize = 64;
pub(crate) const OWNER_DEVICES: usize = 64;
pub(crate) const OWNER_SESSIONS: usize = 512;
pub(crate) const DEVICE_CREDENTIAL_GRANTS: usize = 64;
pub(crate) const MANAGEMENT_PROJECTION_LIMIT: usize = 64;

#[cfg(feature = "test-support")]
pub(crate) fn credential_available(snapshot: &DurableSnapshot, owner: &OpaqueOwnerRef) -> bool {
    snapshot
        .credentials
        .values()
        .filter(|item| &item.owner == owner)
        .count()
        < OWNER_CREDENTIALS
}

#[cfg(feature = "test-support")]
pub(crate) fn identity_available(
    snapshot: &DurableSnapshot,
    owner: &OpaqueOwnerRef,
    device: &DeviceId,
    session: &str,
) -> bool {
    let new_device = !snapshot
        .devices
        .contains_key(&(owner.clone(), device.clone()));
    let new_session = !snapshot
        .sessions
        .contains_key(&(owner.clone(), session.to_owned()));
    (!new_device
        || snapshot
            .devices
            .keys()
            .filter(|(item, _)| item == owner)
            .count()
            < OWNER_DEVICES)
        && (!new_session
            || snapshot
                .sessions
                .keys()
                .filter(|(item, _)| item == owner)
                .count()
                < OWNER_SESSIONS)
}

pub(crate) fn projection_complete(snapshot: &DurableSnapshot, owner: &OpaqueOwnerRef) -> bool {
    snapshot
        .credentials
        .values()
        .filter(|item| &item.owner == owner)
        .count()
        <= OWNER_CREDENTIALS
        && snapshot
            .devices
            .keys()
            .filter(|(item, _)| item == owner)
            .count()
            <= OWNER_DEVICES
        && snapshot
            .sessions
            .keys()
            .filter(|(item, _)| item == owner)
            .count()
            <= OWNER_SESSIONS
}

pub(crate) fn store_complete(snapshot: &DurableSnapshot) -> bool {
    snapshot
        .accounts
        .keys()
        .all(|owner| projection_complete(snapshot, owner))
        && snapshot
            .credentials
            .values()
            .all(|item| snapshot.accounts.contains_key(&item.owner))
        && snapshot
            .devices
            .keys()
            .all(|(owner, _)| snapshot.accounts.contains_key(owner))
        && snapshot
            .sessions
            .keys()
            .all(|(owner, _)| snapshot.accounts.contains_key(owner))
        && crate::authority_grant_limits::capacity_complete(snapshot)
}
