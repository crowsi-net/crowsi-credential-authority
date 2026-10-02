use super::*;

// TR-08: an unknown provider outcome requires signed reconciliation and is never blindly retried.
#[test]
fn tr_08_unknown_provider_result_requires_signed_reconciliation_without_blind_retry() {
    let mut authority = prepared(CredentialClass::OperationOnly);
    let transfer = authority
        .prepare_transfer(transfer_request(TransferMechanism::ProviderReissue))
        .expect("provider reissue prepared");
    authority
        .record_provider_outcome(
            transfer.id(),
            ProviderOperationOutcome::unknown_signed(
                support::provider_operation_ref(),
                "transfer-nonce-01",
                "provider-signature-over-unknown-outcome",
                NOW_MS,
            ),
        )
        .expect("durable unknown outcome");
    let mut authority = authority.reopen_from_durable_store();
    assert_eq!(authority.provider_issue_attempts(transfer.id()), 1);

    let acceptance = TransferAcceptance::new(
        transfer.id().clone(),
        owner_a(),
        target_device(),
        target_key_proof(&owner_a(), &target_device()),
    );
    assert!(matches!(
        authority.accept_transfer(acceptance.clone()),
        Err(AuthorityError::ProviderReconciliationRequired)
    ));
    assert!(matches!(
        authority.retry_provider_reissue(transfer.id()),
        Err(AuthorityError::BlindProviderRetryForbidden)
    ));
    assert_eq!(authority.provider_issue_attempts(transfer.id()), 1);

    assert!(matches!(
        authority.reconcile_provider_outcome(
            transfer.id(),
            SignedProviderReconciliation::not_issued(
                support::provider_operation_ref(),
                "transfer-nonce-01",
                "invalid-signature",
                NOW_MS,
            ),
        ),
        Err(AuthorityError::ProviderReconciliationSignatureInvalid)
    ));
    authority
        .reconcile_provider_outcome(
            transfer.id(),
            SignedProviderReconciliation::not_issued(
                support::provider_operation_ref(),
                "transfer-nonce-01",
                "valid-provider-signature",
                NOW_MS,
            ),
        )
        .expect("signed reconciliation");
    let states = authority.transfer_grant_states(transfer.id());
    assert_eq!(states.source(), GrantState::Active);
    assert_eq!(states.target(), GrantState::Revoked);
    assert!(!states.source_and_target_are_both_authoritative());
    assert_eq!(authority.provider_issue_attempts(transfer.id()), 1);
    let reopened = authority.reopen_from_durable_store();
    assert_eq!(
        reopened.transfer_state(transfer.id()),
        Some(TransferState::Cancelled)
    );
    assert_eq!(reopened.provider_issue_attempts(transfer.id()), 1);
}

// E2E-01: a committed target grant belongs only to B and survives revocation of source A.
#[test]
fn e2e_01_committed_target_survives_source_device_revocation_and_remains_usable() {
    let mut authority = prepared(CredentialClass::Certificate);
    let transfer = authority
        .prepare_transfer(transfer_request(TransferMechanism::ProviderReissue))
        .expect("prepared transfer");
    authority
        .accept_transfer(
            TransferAcceptance::new(
                transfer.id().clone(),
                owner_a(),
                target_device(),
                target_key_proof(&owner_a(), &target_device()),
            )
            .with_provider_receipt(provider_receipt()),
        )
        .expect("committed transfer");
    authority
        .revoke_device(
            &owner_a(),
            &source_device(),
            RevocationCause::DeviceCompromised,
            fresh_step_up(&owner_a(), &source_device()),
        )
        .expect("source A revoked");

    assert_eq!(
        authority.grant_state(transfer.source_grant_id()),
        Some(GrantState::Revoked)
    );
    assert_eq!(
        authority.grant_state(transfer.target_grant_id()),
        Some(GrantState::Active)
    );
    assert!(
        authority
            .authorize_grant_use(GrantUse::new(
                transfer.source_grant_id().clone(),
                owner_a(),
                source_device(),
                audience(),
                action(),
                7,
            ))
            .is_err()
    );
    authority
        .authorize_grant_use(GrantUse::new(
            transfer.target_grant_id().clone(),
            owner_a(),
            target_device(),
            audience(),
            action(),
            7,
        ))
        .expect("target B remains usable after A revocation");
}
