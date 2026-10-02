use super::support::{OPERATION_A, adapter, adapter_snapshot, memory_authority, owner_a};

#[test]
fn host_session_revocation_is_exact_idempotent_and_preserves_siblings() {
    let mut adapter = adapter(memory_authority());
    let receipt = adapter
        .apply_host_session_revocation(OPERATION_A, &owner_a(), "session-a-1", 10, 11)
        .expect("host session revocation");
    assert_eq!(receipt, (10, 11));
    assert_eq!(
        adapter
            .apply_host_session_revocation(OPERATION_A, &owner_a(), "session-a-1", 10, 11)
            .expect("exact replay"),
        receipt
    );

    let snapshot = adapter_snapshot(&adapter);
    let target = snapshot
        .sessions
        .get(&(owner_a(), "session-a-1".into()))
        .expect("target session");
    assert!(target.revoked);
    assert_eq!(target.epoch, 11);
    let same_device_sibling = snapshot
        .sessions
        .get(&(owner_a(), "session-a-2".into()))
        .expect("same-device sibling");
    assert!(!same_device_sibling.revoked);
    assert_eq!(same_device_sibling.epoch, 20);
    let healthy_device_session = snapshot
        .sessions
        .get(&(owner_a(), "session-b-1".into()))
        .expect("healthy-device session");
    assert!(!healthy_device_session.revoked);
    assert_eq!(healthy_device_session.epoch, 30);
}
