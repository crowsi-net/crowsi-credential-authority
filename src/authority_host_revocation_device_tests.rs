use super::support::{
    NOW_MS, OPERATION_A, TemporaryStore, adapter, adapter_snapshot, device_a, owner_a,
    seed_file_store,
};
use crate::{CredentialAuthority, FileAuthorityStore, GrantId, GrantState};

// TR-09: a host-authorized device revocation is exact and durable across a real store reopen.
#[test]
fn tr_09_host_device_revocation_reopens_idempotently_and_preserves_healthy_b() {
    let directory = TemporaryStore::new();
    let store = seed_file_store(directory.path(), directory.anchor());
    let mut first = adapter(CredentialAuthority::with_store(store, NOW_MS));
    let receipt = first
        .apply_host_device_revocation(OPERATION_A, &owner_a(), &device_a(), 7, 8)
        .expect("first host device revocation");
    assert_eq!((receipt.previous_epoch(), receipt.current_epoch()), (7, 8));
    drop(first);

    let reopened_store =
        FileAuthorityStore::open_anchored(directory.path(), directory.anchor()).expect("reopen");
    let mut reopened = adapter(CredentialAuthority::with_store(reopened_store, NOW_MS));
    let replay = reopened
        .apply_host_device_revocation(OPERATION_A, &owner_a(), &device_a(), 7, 8)
        .expect("exact durable replay");
    assert_eq!(replay, receipt);

    let snapshot = adapter_snapshot(&reopened);
    let device = snapshot
        .devices
        .get(&(owner_a(), device_a()))
        .expect("device A");
    assert!(device.revoked);
    assert_eq!(device.epoch, 8);
    for (session_ref, expected_epoch) in [("session-a-1", 11), ("session-a-2", 21)] {
        let session = snapshot
            .sessions
            .get(&(owner_a(), session_ref.into()))
            .expect("device A session");
        assert!(session.revoked);
        assert_eq!(session.epoch, expected_epoch);
    }
    let healthy_session = snapshot
        .sessions
        .get(&(owner_a(), "session-b-1".into()))
        .expect("device B session");
    assert!(!healthy_session.revoked);
    assert_eq!(healthy_session.epoch, 30);
    assert_eq!(
        grant_state(&snapshot, "grant-a-source"),
        GrantState::Revoked
    );
    assert_eq!(
        grant_state(&snapshot, "grant-a-target"),
        GrantState::Revoked
    );
    assert_eq!(grant_state(&snapshot, "grant-b-only"), GrantState::Active);
    assert_eq!(
        grant_state(&snapshot, "grant-a-consumed"),
        GrantState::Consumed
    );
    assert_eq!(
        snapshot
            .used_nonces
            .iter()
            .filter(|nonce| nonce.starts_with("host-revoke:device:"))
            .count(),
        1
    );
}

fn grant_state(snapshot: &crate::DurableSnapshot, id: &str) -> GrantState {
    snapshot
        .grants
        .get(&GrantId::trusted(id))
        .expect("grant")
        .state
}
