#[test]
fn applied_rotation_receipt_replays_after_journal_crash_without_reactivation() {
    let mut value = fixture();
    let expected_binding = binding();
    let receipt = receipt(&value, "receipt-rotation-a");
    value
        .authority
        .store
        .transact(|snapshot| {
            snapshot
                .devices
                .get_mut(&(value.owner.clone(), value.source.clone()))
                .expect("source")
                .revoked = true;
            let current = snapshot
                .grants
                .get_mut(&value.prior_grant)
                .expect("current source grant");
            current.state = GrantState::Revoked;
            let mut historical_admin = current.clone();
            historical_admin.id = GrantId::trusted("aaa-historical-admin");
            historical_admin.action = GrantAction::parse("admin").expect("admin action");
            snapshot
                .grants
                .insert(historical_admin.id.clone(), historical_admin);
            Ok(())
        })
        .expect("local revoke before provider rotation");
    let first = value
        .authority
        .apply_host_revocation_rotation(
            "provider-request-a",
            &value.owner,
            &value.credential,
            &value.source,
            "rotation-nonce",
            &expected_binding,
            receipt.clone(),
            &Verifier,
        )
        .expect("first apply");
    let replay = value
        .authority
        .apply_host_revocation_rotation(
            "provider-request-a",
            &value.owner,
            &value.credential,
            &value.source,
            "rotation-nonce",
            &expected_binding,
            receipt.clone(),
            &Verifier,
        )
        .expect("exact replay after journal crash");
    assert_eq!(first, replay);
    value
        .authority
        .store
        .read(|snapshot| {
            assert_eq!(snapshot.credentials[&value.credential].revision, 2);
            assert!(snapshot.grants.values().any(|grant| {
                grant.credential_id == value.credential
                    && grant.source_device == value.target
                    && grant.target_device == value.target
                    && grant.credential_revision == 2
                    && grant.state == GrantState::Active
            }));
            assert!(!snapshot.grants.values().any(|grant| {
                grant.source_device == value.target
                    && grant.target_device == value.target
                    && grant.action.as_str() == "admin"
                    && grant.state == GrantState::Active
            }));
            Ok(())
        })
        .expect("inspect rotation");
    let mut changed = expected_binding;
    changed.posture_revision = 2;
    assert!(
        value
            .authority
            .apply_host_revocation_rotation(
                "provider-request-a",
                &value.owner,
                &value.credential,
                &value.source,
                "rotation-nonce",
                &changed,
                receipt.clone(),
                &Verifier,
            )
            .is_err()
    );
    assert!(
        value
            .authority
            .apply_host_revocation_rotation(
                "provider-request-b",
                &value.owner,
                &value.credential,
                &value.source,
                "rotation-nonce",
                &binding(),
                receipt,
                &Verifier,
            )
            .is_err()
    );
}
