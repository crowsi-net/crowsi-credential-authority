use super::*;

#[test]
fn file_store_reopen_preserves_replay_revocation_and_unknown_provider_state() {
    let temporary = TemporaryStore::new("reopen");
    let mut authority = provision(&temporary);
    let (request, wire) = grant_request("grant-use-once");
    let grant = authority
        .issue_device_grant_from_assertion(request, &wire, &Verifier, &OwnerMapper)
        .expect("durable grant");
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
        .expect("one use");
    let mut reopened = open_authority(&temporary);
    assert!(matches!(
        reopened.authorize_grant_use(use_request),
        Err(AuthorityError::GrantAlreadyConsumed)
    ));

    let transfer_request = TransferRequest::new(
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
    );
    let transfer_wire = assertion(&source_device(), &audience(), "identity-transfer-unknown");
    let transfer = reopened
        .prepare_transfer_from_assertion(transfer_request, &transfer_wire, &Verifier, &OwnerMapper)
        .expect("durable transfer");
    reopened
        .record_provider_outcome(
            transfer.id(),
            ProviderOperationOutcome::unknown_signed(
                provider_operation_ref(),
                "transfer-nonce-01",
                "provider-signature-over-unknown-outcome",
                NOW_MS,
            ),
            &Verifier,
        )
        .expect("unknown provider outcome");
    let mut reopened_again = open_authority(&temporary);
    assert_eq!(reopened_again.provider_issue_attempts(transfer.id()), 1);
    assert!(matches!(
        reopened_again.accept_transfer(
            TransferAcceptance::new(
                transfer.id().clone(),
                owner_a(),
                target_device(),
                target_key_proof(&owner_a(), &target_device()),
            ),
            &Verifier,
        ),
        Err(AuthorityError::ProviderReconciliationRequired)
    ));
    reopened_again
        .revoke_device(
            &owner_a(),
            &target_device(),
            crowsi_credential_authority::RevocationCause::DeviceCompromised,
            fresh_step_up(&owner_a(), &source_device()),
        )
        .expect("durable revocation");
    assert_eq!(
        open_authority(&temporary).device_epoch(&target_device()),
        Some(8)
    );
}
#[test]
fn file_store_concurrent_grant_use_has_exactly_one_winner() {
    let temporary = TemporaryStore::new("concurrent");
    let mut authority = provision(&temporary);
    let (request, wire) = grant_request("concurrent-use");
    let grant = authority
        .issue_device_grant_from_assertion(request, &wire, &Verifier, &OwnerMapper)
        .expect("grant");
    let use_request = GrantUse::new(
        grant.id().clone(),
        owner_a(),
        target_device(),
        audience(),
        action(),
        grant.target_revocation_epoch(),
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let mut contender = open_authority(&temporary);
        let request = use_request.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            contender.authorize_grant_use(request)
        }));
    }
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(AuthorityError::GrantAlreadyConsumed)))
            .count(),
        1
    );
}
