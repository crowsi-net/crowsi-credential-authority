use super::*;

// CR-07: account, device, audience and action mismatches all fail closed.
#[test]
fn cr_07_wrong_account_device_audience_and_action_are_rejected() {
    let mut authority = prepared(CredentialClass::Certificate);
    assert!(matches!(
        authority.issue_device_grant(grant_request(target_device()).with_owner(owner_b())),
        Err(AuthorityError::IdentityAssertionInvalid)
    ));
    let grant = authority
        .issue_device_grant(grant_request(target_device()))
        .expect("valid grant");
    let valid = GrantUse::new(
        grant.id().clone(),
        owner_a(),
        target_device(),
        audience(),
        action(),
        grant.target_revocation_epoch(),
    );
    assert!(matches!(
        authority.authorize_grant_use(valid.clone().with_owner(owner_b())),
        Err(AuthorityError::WrongOwner)
    ));
    assert!(matches!(
        authority.authorize_grant_use(valid.clone().with_device(unrelated_device())),
        Err(AuthorityError::WrongDevice)
    ));
    assert!(matches!(
        authority.authorize_grant_use(
            valid
                .clone()
                .with_audience(GrantAudience::parse("crowsi://github/admin").expect("audience"))
        ),
        Err(AuthorityError::WrongAudience)
    ));
    assert!(matches!(
        authority.authorize_grant_use(
            valid.with_action(GrantAction::parse("delete-repository").expect("action"))
        ),
        Err(AuthorityError::WrongAction)
    ));
}
// CR-08: device and credential revocation epochs survive reopen and remain narrowly scoped.
#[test]
fn cr_08_revocation_and_epoch_are_durable_without_cross_device_blast_radius() {
    let mut authority = prepared(CredentialClass::Certificate);
    let compromised = authority
        .issue_device_grant(grant_request(target_device()))
        .expect("compromised-device grant");
    let unaffected = authority
        .issue_device_grant(grant_request(unrelated_device()))
        .expect("unaffected-device grant");
    let receipt = authority
        .revoke_device(
            &owner_a(),
            &target_device(),
            RevocationCause::DeviceCompromised,
            fresh_step_up(&owner_a(), &source_device()),
        )
        .expect("device revocation");
    assert_eq!((receipt.previous_epoch(), receipt.current_epoch()), (7, 8));

    let mut reopened = authority.reopen_from_durable_store();
    assert_eq!(reopened.device_epoch(&target_device()), Some(8));
    assert_eq!(
        reopened.grant_state(compromised.id()),
        Some(GrantState::Revoked)
    );
    assert_eq!(
        reopened.grant_state(unaffected.id()),
        Some(GrantState::Active)
    );
    let stale_use = GrantUse::new(
        compromised.id().clone(),
        owner_a(),
        target_device(),
        audience(),
        action(),
        7,
    );
    assert!(matches!(
        reopened.authorize_grant_use(stale_use),
        Err(AuthorityError::StaleRevocationEpoch)
    ));

    let credential_receipt = reopened
        .revoke_credential(
            &owner_a(),
            &credential_id(),
            RevocationCause::ProviderCredentialRotated,
            fresh_step_up(&owner_a(), &source_device()),
        )
        .expect("credential revocation");
    assert_eq!(credential_receipt.revoked_grants(), 1);
    let reopened_again = reopened.reopen_from_durable_store();
    assert_eq!(
        reopened_again.grant_state(unaffected.id()),
        Some(GrantState::Revoked)
    );
}
