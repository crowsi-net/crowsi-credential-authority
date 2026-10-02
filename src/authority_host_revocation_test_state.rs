use super::support::{NOW_MS, device_a, device_b, owner_a, owner_b};
use crate::session::SessionRecord;
use crate::state::DeviceRecord;
use crate::{
    AccountState, CredentialId, DeviceGrant, DeviceId, DurableSnapshot, GrantAction, GrantAudience,
    GrantId, GrantState, OpaqueOwnerRef, ServiceId,
};

pub fn fixture() -> DurableSnapshot {
    let mut snapshot = DurableSnapshot::empty(NOW_MS);
    snapshot.accounts.insert(owner_a(), AccountState::Active);
    snapshot.accounts.insert(owner_b(), AccountState::Active);
    insert_device(&mut snapshot, owner_a(), device_a());
    insert_device(&mut snapshot, owner_a(), device_b());
    insert_device(
        &mut snapshot,
        owner_b(),
        DeviceId::parse("device-owner-b").expect("owner B device"),
    );
    insert_session(&mut snapshot, owner_a(), device_a(), "session-a-1", 10);
    insert_session(&mut snapshot, owner_a(), device_a(), "session-a-2", 20);
    insert_session(&mut snapshot, owner_a(), device_b(), "session-b-1", 30);
    insert_session(
        &mut snapshot,
        owner_b(),
        DeviceId::parse("device-owner-b").expect("owner B device"),
        "session-owner-b",
        40,
    );
    insert_grant(
        &mut snapshot,
        "grant-a-source",
        owner_a(),
        device_a(),
        device_b(),
        GrantState::Active,
    );
    insert_grant(
        &mut snapshot,
        "grant-a-target",
        owner_a(),
        device_b(),
        device_a(),
        GrantState::Pending,
    );
    insert_grant(
        &mut snapshot,
        "grant-b-only",
        owner_a(),
        device_b(),
        device_b(),
        GrantState::Active,
    );
    insert_grant(
        &mut snapshot,
        "grant-a-consumed",
        owner_a(),
        device_a(),
        device_b(),
        GrantState::Consumed,
    );
    snapshot
}

fn insert_device(snapshot: &mut DurableSnapshot, owner: OpaqueOwnerRef, device: DeviceId) {
    snapshot.devices.insert(
        (owner.clone(), device.clone()),
        DeviceRecord {
            owner,
            key_thumbprint: format!("key-{device}"),
            epoch: 7,
            pairwise_subject_ref: "psu_host_revocation".into(),
            issuer: "ihat://identity-authority".into(),
            service_id: ServiceId::parse("service-a").expect("service"),
            posture_state: "healthy".into(),
            posture_revision: 1,
            subject_revocation_epoch: 1,
            service_revocation_epoch: 1,
            session_revocation_epoch: 1,
            key_id: "ihat-key-1".into(),
            enrolled_at_ms: NOW_MS - 10,
            last_seen_at_ms: NOW_MS,
            revoked: false,
        },
    );
}

fn insert_session(
    snapshot: &mut DurableSnapshot,
    owner: OpaqueOwnerRef,
    device: DeviceId,
    session_ref: &str,
    epoch: u64,
) {
    snapshot.sessions.insert(
        (owner.clone(), session_ref.into()),
        SessionRecord {
            owner,
            device_id: device,
            session_ref: session_ref.into(),
            epoch,
            issued_at_ms: NOW_MS - 10,
            expires_at_ms: NOW_MS + 10_000,
            last_seen_at_ms: NOW_MS,
            revoked: false,
        },
    );
}

fn insert_grant(
    snapshot: &mut DurableSnapshot,
    id: &str,
    owner: OpaqueOwnerRef,
    source: DeviceId,
    target: DeviceId,
    state: GrantState,
) {
    let id = GrantId::trusted(id);
    snapshot.grants.insert(
        id.clone(),
        DeviceGrant {
            id,
            owner,
            credential_id: CredentialId::parse("credential-a").expect("credential"),
            credential_revision: 1,
            source_device: source,
            target_device: target,
            audience: GrantAudience::parse("crowsi://service-a/use").expect("audience"),
            action: GrantAction::parse("use").expect("action"),
            source_epoch: 7,
            target_epoch: 7,
            pairwise_subject_ref: "psu_host_revocation".into(),
            identity_issuer: "ihat://identity-authority".into(),
            identity_service_id: ServiceId::parse("service-a").expect("service"),
            source_key_thumbprint: "source-key".into(),
            target_key_thumbprint: "target-key".into(),
            source_posture_revision: 1,
            target_posture_revision: 1,
            source_posture_state: "healthy".into(),
            subject_revocation_epoch: 1,
            service_revocation_epoch: 1,
            session_revocation_epoch: 1,
            identity_key_id: "ihat-key-1".into(),
            expires_at_ms: NOW_MS + 10_000,
            state,
        },
    );
}
