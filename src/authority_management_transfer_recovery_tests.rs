#[test]
fn reconciled_receipt_can_commit_unknown_only_through_management_capability() {
    let mut value = fixture();
    value
        .authority
        .record_provider_outcome(
            value.transfer.id(),
            crate::ProviderOperationOutcome::unknown_signed(
                crate::provider::provider_operation_ref("target-nonce"),
                "target-nonce",
                "valid",
                NOW,
            ),
            &Verifier,
        )
        .expect("durable unknown");
    value.authority.advance_clock(301_000);
    let acceptance = value.acceptance();
    assert!(
        value
            .authority
            .accept_transfer(acceptance.clone(), &Verifier)
            .is_err()
    );
    assert_eq!(
        value
            .authority
            .accept_management_transfer(acceptance, &Verifier, &value.authorization)
            .expect("reconciled management receipt")
            .state(),
        TransferState::Committed
    );
}

#[test]
fn committed_prepare_is_recovered_before_current_identity_checks() {
    let mut value = fixture();
    let expected = value.transfer.id().clone();
    value
        .authority
        .store
        .transact(|snapshot| {
            snapshot
                .devices
                .get_mut(&(value.owner.clone(), value.source.clone()))
                .expect("source")
                .revoked = true;
            snapshot
                .devices
                .get_mut(&(value.owner.clone(), value.target.clone()))
                .expect("target")
                .posture_revision = 2;
            Ok(())
        })
        .expect("identity drift after core prepare");
    value.authority.advance_clock(301_000);
    let service = ServiceId::parse("service-a").expect("service");
    let recovered = value
        .authority
        .recover_management_transfer(
            &value.owner,
            &value.credential,
            &service,
            &value.source,
            &value.target,
            "target-nonce",
            &value.authorization,
            &binding(&value.source, &service),
            &binding(&value.target, &service),
        )
        .expect("recover query")
        .expect("prepared transfer");
    assert_eq!(recovered.id(), &expected);
    assert!(
        value
            .authority
            .recover_management_transfer(
                &value.owner,
                &value.credential,
                &service,
                &value.source,
                &value.target,
                "target-nonce",
                &format!("sha256:{}", "b".repeat(64)),
                &binding(&value.source, &service),
                &binding(&value.target, &service),
            )
            .is_err()
    );
}
