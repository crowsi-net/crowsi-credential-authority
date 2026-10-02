use super::*;

// CR-04: a recent source-device step-up is mandatory for every grant.
#[test]
fn cr_04_device_grant_requires_fresh_step_up_from_the_source_device() {
    let mut authority = prepared(CredentialClass::Certificate);
    let stale = StepUpProof::verified(
        owner_a(),
        source_device(),
        NOW_MS - 600_000,
        NOW_MS - 300_000,
    );
    assert!(matches!(
        authority.issue_device_grant(grant_request(target_device()).with_step_up(stale)),
        Err(AuthorityError::FreshStepUpRequired)
    ));
    assert!(matches!(
        authority.issue_device_grant(
            grant_request(target_device())
                .with_step_up(fresh_step_up(&owner_a(), &unrelated_device()))
        ),
        Err(AuthorityError::StepUpDeviceMismatch)
    ));
}
// CR-05: the target proves possession of its registered, device-unique key.
#[test]
fn cr_05_device_grant_requires_target_key_possession_proof() {
    let mut authority = prepared(CredentialClass::Certificate);
    let wrong_key = TargetKeyProof::verified(
        owner_a(),
        target_device(),
        "key-thumbprint:not-the-registered-key",
        "transfer-nonce-01",
        NOW_MS,
    );
    assert!(matches!(
        authority
            .issue_device_grant(grant_request(target_device()).with_target_key_proof(wrong_key)),
        Err(AuthorityError::TargetKeyProofInvalid)
    ));
    assert!(matches!(
        authority.issue_device_grant(
            grant_request(target_device())
                .with_target_key_proof(target_key_proof(&owner_a(), &unrelated_device(),))
        ),
        Err(AuthorityError::TargetDeviceMismatch)
    ));
}

// CR-06: grants have a hard TTL, are one-use, and remain consumed after clock rollback.
#[test]
fn cr_06_device_grant_is_ttl_bounded_one_use_and_replay_safe() {
    let mut authority = prepared(CredentialClass::Certificate);
    let grant = authority
        .issue_device_grant(grant_request(target_device()))
        .expect("device grant");
    let use_request = GrantUse::new(
        grant.id().clone(),
        owner_a(),
        target_device(),
        audience(),
        action(),
        grant.target_revocation_epoch(),
    );
    authority
        .authorize_grant_use(use_request.clone())
        .expect("first and only use");
    let mut reopened_after_use = authority.reopen_from_durable_store();
    assert!(matches!(
        reopened_after_use.authorize_grant_use(use_request),
        Err(AuthorityError::GrantAlreadyConsumed)
    ));

    let expiring = authority
        .issue_device_grant(grant_request(target_device()))
        .expect("expiring grant");
    authority.advance_clock(GRANT_TTL_MS + 1);
    let expired_use = GrantUse::new(
        expiring.id().clone(),
        owner_a(),
        target_device(),
        audience(),
        action(),
        expiring.target_revocation_epoch(),
    );
    assert!(matches!(
        authority.authorize_grant_use(expired_use.clone()),
        Err(AuthorityError::GrantExpired)
    ));
    let mut reopened_after_expiry = authority.reopen_from_durable_store();
    reopened_after_expiry.rewind_clock_to(NOW_MS);
    assert!(matches!(
        reopened_after_expiry.authorize_grant_use(expired_use),
        Err(AuthorityError::GrantExpired)
    ));

    let mut nonce_authority = prepared(CredentialClass::Certificate);
    let nonce_bound = grant_request(target_device());
    nonce_authority
        .issue_device_grant(nonce_bound.clone())
        .expect("first nonce use");
    assert!(matches!(
        nonce_authority.issue_device_grant(nonce_bound),
        Err(AuthorityError::TargetKeyProofInvalid)
    ));
}
