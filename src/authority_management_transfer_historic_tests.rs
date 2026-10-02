#[test]
fn historic_management_commit_renews_target_and_revokes_every_source_grant() {
    let mut value = fixture();
    value.authority.advance_clock(301_000);
    value
        .authority
        .store
        .transact(|snapshot| {
            crate::authority_grant_limits::expire(snapshot, NOW + 301_000);
            assert_eq!(
                snapshot.grants[value.transfer.source_grant_id()].state,
                GrantState::Expired
            );
            assert_eq!(
                snapshot.grants[value.transfer.target_grant_id()].state,
                GrantState::Expired
            );
            Ok(())
        })
        .expect("unrelated mutation expiry sweep");
    let result = value
        .authority
        .accept_management_transfer(value.acceptance(), &Verifier, &value.authorization)
        .expect("historic management commit");
    assert_eq!(result.state(), TransferState::Committed);
    assert_eq!(
        value.authority.grant_state(&value.prior_grant),
        Some(GrantState::Revoked)
    );
    assert_eq!(
        value.authority.grant_state(result.target_grant_id()),
        Some(GrantState::Active)
    );
    let use_request = GrantUse::new(
        result.target_grant_id().clone(),
        value.owner,
        value.target,
        value.audience,
        value.action,
        1,
    );
    value
        .authority
        .authorize_grant_use(use_request.clone())
        .expect("renewed target usable");
    assert!(value.authority.authorize_grant_use(use_request).is_err());
}

#[test]
fn historic_management_commit_rejects_target_identity_service_drift() {
    let mut value = fixture();
    value
        .authority
        .store
        .transact(|snapshot| {
            snapshot
                .devices
                .get_mut(&(value.owner.clone(), value.target.clone()))
                .expect("target")
                .service_id = ServiceId::parse("service-b").expect("service b");
            Ok(())
        })
        .expect("drift");
    value.authority.advance_clock(301_000);
    assert!(
        value
            .authority
            .accept_management_transfer(value.acceptance(), &Verifier, &value.authorization)
            .is_err()
    );
    assert_eq!(
        value.authority.transfer_state(value.transfer.id()),
        Some(TransferState::Prepared)
    );
}

#[test]
fn not_issued_cancel_is_exactly_idempotent() {
    let mut value = fixture();
    let reconciliation = crate::SignedProviderReconciliation::not_issued(
        crate::provider::provider_operation_ref("target-nonce"),
        "target-nonce",
        "valid",
        NOW,
    );
    value
        .authority
        .reconcile_provider_not_issued(value.transfer.id(), reconciliation.clone(), &Verifier)
        .expect("first cancel");
    value
        .authority
        .reconcile_provider_not_issued(value.transfer.id(), reconciliation, &Verifier)
        .expect("exact retry");
    assert_eq!(
        value.authority.transfer_state(value.transfer.id()),
        Some(TransferState::Cancelled)
    );
    assert_eq!(
        value
            .authority
            .grant_state(value.transfer.source_grant_id()),
        None
    );
    assert_eq!(
        value
            .authority
            .grant_state(value.transfer.target_grant_id()),
        None
    );
    assert_eq!(
        value.authority.grant_state(&value.prior_grant),
        Some(GrantState::Active)
    );
}
