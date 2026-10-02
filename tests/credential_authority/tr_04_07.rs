use super::*;

// TR-04: every credential class uses provider rotation; no raw-material path exists.
#[test]
fn tr_04_every_credential_class_requires_provider_rotation_receipt() {
    for class in [
        CredentialClass::Certificate,
        CredentialClass::DelegatedToken,
        CredentialClass::OperationOnly,
    ] {
        let mut authority = prepared(class);
        let transfer = authority
            .prepare_transfer(transfer_request(TransferMechanism::ProviderReissue))
            .expect("provider rotation prepared");
        assert!(matches!(
            authority.accept_transfer(TransferAcceptance::new(
                transfer.id().clone(),
                owner_a(),
                target_device(),
                target_key_proof(&owner_a(), &target_device())
            )),
            Err(AuthorityError::ProviderReissueReceiptRequired)
        ));
    }
}

// TR-05: provider reissue must return a verified, target-bound revision receipt.
#[test]
fn tr_05_provider_reissue_receipt_is_required_before_target_activation() {
    let mut authority = prepared(CredentialClass::OperationOnly);
    let transfer = authority
        .prepare_transfer(transfer_request(TransferMechanism::ProviderReissue))
        .expect("provider reissue prepared");
    let acceptance = TransferAcceptance::new(
        transfer.id().clone(),
        owner_a(),
        target_device(),
        target_key_proof(&owner_a(), &target_device()),
    );
    assert!(matches!(
        authority.accept_transfer(acceptance.clone()),
        Err(AuthorityError::ProviderReissueReceiptRequired)
    ));
    let receipt = authority
        .accept_transfer(acceptance.with_provider_receipt(provider_receipt()))
        .expect("verified provider receipt");
    assert_eq!(receipt.provider_revision(), Some(4));
    assert_eq!(
        authority.grant_state(transfer.target_grant_id()),
        Some(GrantState::Active)
    );
}

// TR-06: an exact committed result is idempotent while substituted receipts remain rejected.
#[test]
fn tr_06_acceptance_and_receipt_replay_or_tampering_are_rejected() {
    let mut authority = prepared(CredentialClass::OperationOnly);
    let transfer = authority
        .prepare_transfer(transfer_request(TransferMechanism::ProviderReissue))
        .expect("provider reissue prepared");
    let acceptance = TransferAcceptance::new(
        transfer.id().clone(),
        owner_a(),
        target_device(),
        target_key_proof(&owner_a(), &target_device()),
    );
    assert!(matches!(
        authority.accept_transfer(
            acceptance
                .clone()
                .with_provider_receipt(provider_receipt().with_revision(99))
        ),
        Err(AuthorityError::ProviderReceiptInvalid)
    ));
    assert!(matches!(
        authority.accept_transfer(
            acceptance
                .clone()
                .with_provider_receipt(provider_receipt().with_target_device(source_device()))
        ),
        Err(AuthorityError::ProviderReceiptInvalid)
    ));
    let valid = acceptance.with_provider_receipt(provider_receipt());
    let first = authority
        .accept_transfer(valid.clone())
        .expect("first and only acceptance");
    let mut reopened = authority.reopen_from_durable_store();
    assert_eq!(
        reopened
            .accept_transfer(valid)
            .expect("exact committed replay"),
        first
    );
}
// TR-07: cancellation before commit preserves source authority and permanently disables target.
#[test]
fn tr_07_precommit_cancel_preserves_source_and_disables_target() {
    let mut authority = prepared(CredentialClass::Certificate);
    let transfer = authority
        .prepare_transfer(transfer_request(TransferMechanism::ProviderReissue))
        .expect("prepared transfer");
    let cancellation = authority
        .cancel_transfer(TransferCancellation::new(
            transfer.id().clone(),
            owner_a(),
            source_device(),
            fresh_step_up(&owner_a(), &source_device()),
        ))
        .expect("precommit cancellation");
    assert_eq!(cancellation.state(), TransferState::Cancelled);
    let states = authority.transfer_grant_states(transfer.id());
    assert_eq!(states.source(), GrantState::Active);
    assert_eq!(states.target(), GrantState::Revoked);
    assert!(!states.source_and_target_are_both_authoritative());
    assert!(matches!(
        authority.accept_transfer(TransferAcceptance::new(
            transfer.id().clone(),
            owner_a(),
            target_device(),
            target_key_proof(&owner_a(), &target_device()),
        )),
        Err(AuthorityError::TransferCancelled)
    ));

    let reopened = authority.reopen_from_durable_store();
    assert_eq!(
        reopened.transfer_state(transfer.id()),
        Some(TransferState::Cancelled)
    );
}
