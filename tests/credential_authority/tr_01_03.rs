use super::*;

// TR-01: prepare never authorizes the target while the source is still active.
#[test]
fn tr_01_prepare_keeps_source_active_and_target_pending() {
    let mut authority = prepared(CredentialClass::Certificate);
    let transfer = authority
        .prepare_transfer(transfer_request(TransferMechanism::ProviderReissue))
        .expect("prepared transfer");
    assert_eq!(transfer.state(), TransferState::Prepared);
    assert_eq!(
        authority.grant_state(transfer.source_grant_id()),
        Some(GrantState::Active)
    );
    assert_eq!(
        authority.grant_state(transfer.target_grant_id()),
        Some(GrantState::Pending)
    );
}
// TR-02: commit atomically revokes the source grant and activates the target grant.
#[test]
fn tr_02_commit_atomically_revokes_source_and_activates_target() {
    let mut authority = prepared(CredentialClass::Certificate);
    let transfer = authority
        .prepare_transfer(transfer_request(TransferMechanism::ProviderReissue))
        .expect("prepared transfer");
    let receipt = authority
        .accept_transfer(
            TransferAcceptance::new(
                transfer.id().clone(),
                owner_a(),
                target_device(),
                target_key_proof(&owner_a(), &target_device()),
            )
            .with_provider_receipt(provider_receipt()),
        )
        .expect("atomic transfer");
    assert_eq!(receipt.state(), TransferState::Committed);
    let states = authority.transfer_grant_states(transfer.id());
    assert_eq!(states.source(), GrantState::Revoked);
    assert_eq!(states.target(), GrantState::Active);
    assert!(!states.source_and_target_are_both_authoritative());
    let reopened = authority.reopen_from_durable_store();
    let durable_states = reopened.transfer_grant_states(transfer.id());
    assert_eq!(durable_states.source(), GrantState::Revoked);
    assert_eq!(durable_states.target(), GrantState::Active);
}

// TR-03: every interrupted commit rolls back without ever creating dual authority.
#[test]
fn tr_03_intermediate_failures_never_leave_double_authority() {
    for fail_point in [
        CommitFailPoint::BeforeSourceRevoke,
        CommitFailPoint::AfterSourceRevokeBeforeTargetActivate,
        CommitFailPoint::BeforeReceiptPersist,
    ] {
        let mut authority = prepared(CredentialClass::Certificate);
        let transfer = authority
            .prepare_transfer(transfer_request(TransferMechanism::ProviderReissue))
            .expect("prepared transfer");
        authority.fail_next_commit_at(fail_point);
        assert!(matches!(
            authority.accept_transfer(
                TransferAcceptance::new(
                    transfer.id().clone(),
                    owner_a(),
                    target_device(),
                    target_key_proof(&owner_a(), &target_device()),
                )
                .with_provider_receipt(provider_receipt())
            ),
            Err(AuthorityError::AtomicCommitFailed)
        ));
        let states = authority.transfer_grant_states(transfer.id());
        assert_eq!(states.source(), GrantState::Active);
        assert_eq!(states.target(), GrantState::Pending);
        assert!(!states.source_and_target_are_both_authoritative());
    }
}
