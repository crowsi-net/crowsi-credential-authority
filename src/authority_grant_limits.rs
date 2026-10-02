use std::collections::BTreeMap;

use crate::{CredentialId, DurableSnapshot, GrantState, OpaqueOwnerRef};

pub(crate) fn expire(snapshot: &mut DurableSnapshot, now: u64) {
    for grant in snapshot.grants.values_mut() {
        if matches!(grant.state, GrantState::Active | GrantState::Pending)
            && grant.expires_at_ms <= now
        {
            grant.state = GrantState::Expired;
        }
    }
}

#[cfg(feature = "test-support")]
pub(crate) fn one_available(
    snapshot: &DurableSnapshot,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
) -> bool {
    count(snapshot, owner, credential) < cap()
}

pub(crate) fn transfer_available(
    snapshot: &DurableSnapshot,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
) -> bool {
    count(snapshot, owner, credential) + 2 <= cap()
}

pub(crate) fn capacity_complete(snapshot: &DurableSnapshot) -> bool {
    let mut counts = BTreeMap::<(OpaqueOwnerRef, CredentialId), usize>::new();
    snapshot
        .grants
        .values()
        .filter(|grant| reserves_capacity(snapshot, grant))
        .all(|grant| increment(&mut counts, &grant.owner, &grant.credential_id))
}

fn count(snapshot: &DurableSnapshot, owner: &OpaqueOwnerRef, credential: &CredentialId) -> usize {
    snapshot
        .grants
        .values()
        .filter(|grant| {
            grant.owner == *owner
                && grant.credential_id == *credential
                && reserves_capacity(snapshot, grant)
        })
        .count()
}

fn reserves_capacity(snapshot: &DurableSnapshot, grant: &crate::DeviceGrant) -> bool {
    matches!(grant.state, GrantState::Active | GrantState::Pending)
        || (grant.state == GrantState::Revoked
            && snapshot
                .credentials
                .get(&grant.credential_id)
                .is_some_and(|credential| {
                    credential.owner == grant.owner
                        && credential.revision == grant.credential_revision
                })
            && device_epoch_invalid(snapshot, grant))
}

fn device_epoch_invalid(snapshot: &DurableSnapshot, grant: &crate::DeviceGrant) -> bool {
    snapshot
        .devices
        .get(&(grant.owner.clone(), grant.source_device.clone()))
        .is_none_or(|record| record.revoked || record.epoch != grant.source_epoch)
        || snapshot
            .devices
            .get(&(grant.owner.clone(), grant.target_device.clone()))
            .is_none_or(|record| record.revoked || record.epoch != grant.target_epoch)
}

fn increment(
    counts: &mut BTreeMap<(OpaqueOwnerRef, CredentialId), usize>,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
) -> bool {
    let count = counts
        .entry((owner.clone(), credential.clone()))
        .or_default();
    *count += 1;
    *count <= cap()
}

const fn cap() -> usize {
    crate::authority_limits::DEVICE_CREDENTIAL_GRANTS
}
