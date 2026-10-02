#[test]
fn historic_rotation_applies_revision_without_resurrecting_expired_grant() {
    let mut value = fixture();
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
                .expect("current grant");
            current.expires_at_ms = NOW + 30_000;
            Ok(())
        })
        .expect("historic binding");
    value.authority.advance_clock(301_000);
    value
        .authority
        .store
        .transact(|snapshot| {
            crate::authority_grant_limits::expire(snapshot, NOW + 301_000);
            assert_eq!(
                snapshot.grants[&value.prior_grant].state,
                GrantState::Expired
            );
            Ok(())
        })
        .expect("unrelated mutation expiry sweep");
    value
        .authority
        .apply_host_revocation_rotation(
            "provider-request-expired",
            &value.owner,
            &value.credential,
            &value.source,
            "rotation-nonce",
            &binding_with_expiry(NOW + 30_000),
            receipt(&value, "receipt-expired"),
            &Verifier,
        )
        .expect("historic receipt applies provider revision");
    value
        .authority
        .store
        .read(|snapshot| {
            assert_eq!(snapshot.credentials[&value.credential].revision, 2);
            assert!(!snapshot.grants.values().any(|grant| {
                grant.source_device == value.target
                    && grant.target_device == value.target
                    && matches!(grant.state, GrantState::Active | GrantState::Pending)
            }));
            Ok(())
        })
        .expect("inspect expired rotation");
}

fn receipt(
    value: &super::authority_management_transfer_test_support::Fixture,
    id: &str,
) -> ProviderReissueReceipt {
    ProviderReissueReceipt::signed(
        id,
        value.owner.clone(),
        ServiceId::parse("service-a").expect("service"),
        ProviderAccountRef::parse("provider-a").expect("provider"),
        value.credential.clone(),
        1,
        2,
        value.target.clone(),
        "rotation-nonce",
        NOW,
        "valid",
    )
}

fn binding() -> RevocationTargetBindingV1 {
    binding_with_expiry(NOW + 900_000)
}

fn binding_with_expiry(expires_at_ms: u64) -> RevocationTargetBindingV1 {
    RevocationTargetBindingV1 {
        credential_revision: 1,
        service_id: "service-a".into(),
        pairwise_subject: "psu_service-a_subject".into(),
        issuer: "ihat://authority".into(),
        device_proof_key_ref: "key:device-target".into(),
        device_epoch: 1,
        posture_state: "compliant".into(),
        posture_revision: 1,
        subject_epoch: 1,
        service_epoch: 1,
        session_epoch: 1,
        identity_key_id: "identity-key".into(),
        grants: vec![crate::management_v2_record::RevocationGrantBindingV1 {
            grant_id: "prior-source-grant".into(),
            source_device_ref: "device-source".into(),
            target_device_ref: "device-source".into(),
            audience: "crowsi://service-a/operate".into(),
            action: "operate".into(),
            credential_revision: 1,
            expires_at_ms,
            state: "active".into(),
        }],
    }
}
