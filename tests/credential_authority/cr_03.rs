use super::*;

// CR-03: a grant is bound to one owner, credential, source, target, audience and action.
#[test]
fn cr_03_device_grant_has_complete_non_downgradable_binding() {
    let mut authority = prepared(CredentialClass::Certificate);
    let grant = authority
        .issue_device_grant(grant_request(target_device()))
        .expect("device grant");
    assert_eq!(grant.owner(), &owner_a());
    assert_eq!(grant.credential_id(), &credential_id());
    assert_eq!(grant.source_device(), &source_device());
    assert_eq!(grant.target_device(), &target_device());
    assert_eq!(grant.audience(), &audience());
    assert_eq!(grant.action(), &action());
    assert_eq!(grant.source_revocation_epoch(), 7);
    assert_eq!(grant.target_revocation_epoch(), 7);

    let mut production = CredentialAuthority::with_store(MemoryStore::new(NOW_MS), NOW_MS);
    let registration_audience =
        GrantAudience::parse("crowsi://identity/register").expect("registration audience");
    for (device, nonce) in [
        (source_device(), "identity-register-source"),
        (target_device(), "identity-register-target"),
    ] {
        production
            .register_device_from_assertion(
                &signed_identity_assertion(&device, &registration_audience, nonce),
                &registration_audience,
                &FixedIdentityVerifier,
                &FixedOwnerMapper,
            )
            .expect("verified device registration");
    }
    production
        .register_credential(CredentialRegistration::metadata_only(
            credential_id(),
            owner_a(),
            service(),
            provider_account(),
            "production assertion fixture",
            CredentialClass::Certificate,
            3,
        ))
        .expect("metadata registration");
    let grant_assertion =
        signed_identity_assertion(&source_device(), &audience(), "identity-grant-source");
    production
        .issue_device_grant_from_assertion(
            grant_request(target_device()),
            &grant_assertion,
            &FixedIdentityVerifier,
            &FixedOwnerMapper,
        )
        .expect("assertion-bound production grant");
    assert!(matches!(
        production.issue_device_grant_from_assertion(
            grant_request(target_device()),
            &grant_assertion,
            &FixedIdentityVerifier,
            &FixedOwnerMapper,
        ),
        Err(AuthorityError::IdentityAssertionReplay)
    ));
    let mut stale_epoch_authority =
        CredentialAuthority::with_store(MemoryStore::new(NOW_MS), NOW_MS);
    assert!(matches!(
        stale_epoch_authority.register_device_from_assertion(
            &signed_identity_assertion(
                &source_device(),
                &registration_audience,
                "identity-stale-authoritative-epoch",
            ),
            &registration_audience,
            &StaleEpochVerifier,
            &FixedOwnerMapper,
        ),
        Err(AuthorityError::StaleRevocationEpoch)
    ));
}
