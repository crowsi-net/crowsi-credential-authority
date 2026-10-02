use super::support::{
    OPERATION_A, OPERATION_B, adapter, adapter_snapshot, device_a, memory_authority, owner_a,
    owner_b,
};
use crate::{AuthorityError, CoelaAuthorityAdapter};

#[test]
fn host_device_revocation_rejects_wrong_binding_without_side_effects() {
    for (operation, owner, previous, current, expected) in [
        (
            "not-an-operation-id",
            owner_a(),
            7,
            8,
            AuthorityError::InvalidValue("host revocation"),
        ),
        (
            OPERATION_A,
            owner_a(),
            6,
            7,
            AuthorityError::StaleRevocationEpoch,
        ),
        (
            OPERATION_A,
            owner_a(),
            7,
            9,
            AuthorityError::InvalidValue("host revocation"),
        ),
        (OPERATION_A, owner_b(), 7, 8, AuthorityError::WrongDevice),
    ] {
        let mut adapter = adapter(memory_authority());
        let before = fingerprint(&adapter);
        let error = adapter
            .apply_host_device_revocation(operation, &owner, &device_a(), previous, current)
            .expect_err("wrong binding must fail closed");
        assert_eq!(error, expected);
        assert_eq!(fingerprint(&adapter), before);
    }
}

#[test]
fn completed_device_revocation_cannot_be_replayed_under_another_operation() {
    let mut adapter = adapter(memory_authority());
    adapter
        .apply_host_device_revocation(OPERATION_A, &owner_a(), &device_a(), 7, 8)
        .expect("authorized operation");
    let before = fingerprint(&adapter);
    assert_eq!(
        adapter
            .apply_host_device_revocation(OPERATION_B, &owner_a(), &device_a(), 7, 8)
            .expect_err("substituted operation must fail"),
        AuthorityError::StaleRevocationEpoch
    );
    assert_eq!(fingerprint(&adapter), before);
}

#[test]
fn host_session_revocation_rejects_mismatch_and_substituted_replay() {
    let mut adapter = adapter(memory_authority());
    for (operation, owner, previous, current) in [
        ("invalid", owner_a(), 10, 11),
        (OPERATION_A, owner_a(), 9, 10),
        (OPERATION_A, owner_b(), 10, 11),
    ] {
        let before = fingerprint(&adapter);
        assert!(
            adapter
                .apply_host_session_revocation(operation, &owner, "session-a-1", previous, current,)
                .is_err()
        );
        assert_eq!(fingerprint(&adapter), before);
    }
    adapter
        .apply_host_session_revocation(OPERATION_A, &owner_a(), "session-a-1", 10, 11)
        .expect("authorized session operation");
    let before = fingerprint(&adapter);
    assert!(
        adapter
            .apply_host_session_revocation(OPERATION_B, &owner_a(), "session-a-1", 10, 11)
            .is_err()
    );
    assert_eq!(fingerprint(&adapter), before);
}

fn fingerprint(
    adapter: &CoelaAuthorityAdapter<
        crate::store::MemoryStore,
        super::support::TestVerifier,
        super::support::TestVerifier,
        super::support::TestVerifier,
    >,
) -> String {
    let snapshot = adapter_snapshot(adapter);
    let devices: Vec<_> = snapshot
        .devices
        .iter()
        .map(|((owner, device), record)| {
            (
                owner.as_str(),
                device.as_str(),
                record.epoch,
                record.revoked,
            )
        })
        .collect();
    let sessions: Vec<_> = snapshot
        .sessions
        .iter()
        .map(|((owner, session), record)| {
            (
                owner.as_str(),
                session.as_str(),
                record.epoch,
                record.revoked,
            )
        })
        .collect();
    let grants: Vec<_> = snapshot
        .grants
        .iter()
        .map(|(id, grant)| (id.as_str(), grant.state))
        .collect();
    format!(
        "{}|{devices:?}|{sessions:?}|{grants:?}|{:?}",
        snapshot.version, snapshot.used_nonces
    )
}
