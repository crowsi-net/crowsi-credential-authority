#[path = "support/mod.rs"]
mod support;

use crowsi_credential_authority::{
    CredentialClass, ProviderReissueReceipt, SignedProviderReconciliation, TransferAcceptance,
    TransferMechanism, TransferRequest, TransferState,
};
use support::*;

const EXACT_RETRY_IDENTITY_NONCE: &str = "provider-saga-exact-identity";

fn prepared() -> (TestAuthority, crowsi_credential_authority::TransferReceipt) {
    let mut authority = authority();
    register_device(&mut authority, &owner_a(), &source_device());
    register_device(&mut authority, &owner_a(), &target_device());
    register_credential(&mut authority, &owner_a(), CredentialClass::OperationOnly);
    let transfer = authority
        .prepare_transfer_with_identity_nonce(request(), EXACT_RETRY_IDENTITY_NONCE)
        .expect("durable authority prepare");
    (authority, transfer)
}

fn request() -> TransferRequest {
    TransferRequest::new(
        owner_a(),
        credential_id(),
        source_device(),
        target_device(),
        audience(),
        action(),
        TransferMechanism::ProviderReissue,
        GRANT_TTL_MS,
        fresh_step_up(&owner_a(), &source_device()),
        target_key_proof(&owner_a(), &target_device()),
    )
}

fn receipt() -> ProviderReissueReceipt {
    ProviderReissueReceipt::signed(
        "provider-receipt-01",
        owner_a(),
        service(),
        provider_account(),
        credential_id(),
        3,
        4,
        target_device(),
        "transfer-nonce-01",
        NOW_MS,
        "valid-provider-reissue-signature",
    )
}

#[test]
fn resume_after_provider_success_before_prepare_returns_same_durable_intent() {
    let (authority, first) = prepared();
    let mut restarted = authority.reopen_from_durable_store();
    let resumed = restarted
        .prepare_transfer_with_identity_nonce(request(), EXACT_RETRY_IDENTITY_NONCE)
        .expect("idempotent resume");
    assert_eq!(resumed, first);
}

#[test]
fn resume_after_authority_commit_before_journal_finish_is_exactly_once() {
    let (mut authority, transfer) = prepared();
    let acceptance = TransferAcceptance::new(
        transfer.id().clone(),
        owner_a(),
        target_device(),
        target_key_proof(&owner_a(), &target_device()),
    )
    .with_provider_receipt(receipt());
    let first = authority
        .accept_transfer(acceptance.clone())
        .expect("commit");
    let second = authority
        .reopen_from_durable_store()
        .accept_transfer(acceptance)
        .expect("idempotent recovery");
    assert_eq!(first, second);
}

#[test]
fn not_issued_finishes_cancelled_terminal_without_prior_unknown_record() {
    let (mut authority, transfer) = prepared();
    authority
        .reconcile_provider_not_issued(
            transfer.id(),
            SignedProviderReconciliation::not_issued(
                provider_operation_ref(),
                "transfer-nonce-01",
                "valid-provider-signature",
                NOW_MS,
            ),
        )
        .expect("signed provider says no side effect");
    assert_eq!(
        authority.transfer_state(transfer.id()),
        Some(TransferState::Cancelled)
    );
}
