use super::*;

// CR-09: credential rotation revokes only grants pinned to the superseded revision.
#[test]
fn cr_09_rotation_revokes_only_the_superseded_credential_revision() {
    let mut authority = prepared(CredentialClass::OperationOnly);
    let revision_three = authority
        .issue_device_grant(grant_request(target_device()))
        .expect("revision-three grant");
    assert_eq!(revision_three.credential_revision(), 3);

    let rotation = authority
        .record_provider_reissue(
            &owner_a(),
            &credential_id(),
            provider_receipt(),
            fresh_step_up(&owner_a(), &source_device()),
        )
        .expect("provider-backed rotation");
    assert_eq!(
        (rotation.previous_revision(), rotation.current_revision()),
        (3, 4)
    );
    assert_eq!(
        authority.grant_state(revision_three.id()),
        Some(GrantState::Revoked)
    );

    let revision_four = authority
        .issue_device_grant(grant_request(unrelated_device()))
        .expect("revision-four grant");
    assert_eq!(revision_four.credential_revision(), 4);
    authority
        .revoke_credential_revision(
            &owner_a(),
            &credential_id(),
            3,
            RevocationCause::ProviderCredentialRotated,
        )
        .expect("idempotent old-revision revocation");
    assert_eq!(
        authority.grant_state(revision_four.id()),
        Some(GrantState::Active)
    );
}
// CR-10: unlink/close fails closed without asking custody to delete provider secrets.
#[test]
fn cr_10_account_unlink_or_close_disables_access_without_secret_deletion() {
    for close_request in [
        AccountClosureRequest::unlink(owner_a(), fresh_step_up(&owner_a(), &source_device())),
        AccountClosureRequest::close(owner_a(), fresh_step_up(&owner_a(), &source_device())),
    ] {
        let mut authority = prepared(CredentialClass::Certificate);
        let grant = authority
            .issue_device_grant(grant_request(target_device()))
            .expect("pre-closure grant");
        let receipt = authority
            .apply_account_closure(close_request)
            .expect("fail-closed account lifecycle transition");

        assert!(matches!(
            receipt.account_state(),
            AccountState::Unlinked | AccountState::Closed
        ));
        assert!(!receipt.secret_deletion_attempted());
        assert_eq!(authority.custody_secret_deletion_requests(), 0);
        assert_eq!(authority.grant_state(grant.id()), Some(GrantState::Revoked));
        assert!(matches!(
            authority.issue_device_grant(grant_request(target_device())),
            Err(AuthorityError::AccountUnavailable)
        ));

        let reopened = authority.reopen_from_durable_store();
        assert!(matches!(
            reopened.account_state(&owner_a()),
            Some(AccountState::Unlinked | AccountState::Closed)
        ));
        assert_eq!(reopened.custody_secret_deletion_requests(), 0);
    }
}
