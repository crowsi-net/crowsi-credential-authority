#[test]
fn repeated_not_issued_management_attempts_release_transient_capacity() {
    let mut value = fixture();
    let initial = crate::SignedProviderReconciliation::not_issued(
        crate::provider::provider_operation_ref("target-nonce"),
        "target-nonce",
        "valid",
        NOW,
    );
    value
        .authority
        .reconcile_provider_not_issued(value.transfer.id(), initial, &Verifier)
        .expect("initial cancel");
    for index in 1..=40 {
        let (transfer, nonce) = value.prepare_attempt(index);
        let reconciliation = crate::SignedProviderReconciliation::not_issued(
            crate::provider::provider_operation_ref(&nonce),
            nonce,
            "valid",
            NOW,
        );
        value
            .authority
            .reconcile_provider_not_issued(transfer.id(), reconciliation, &Verifier)
            .expect("bounded cancellation cleanup");
        if index % 7 == 0 {
            value.authority = value.authority.reopen_from_durable_store();
        }
    }
    value.prepare_attempt(41);
}

#[test]
fn cancelled_transient_grants_do_not_become_rotation_reservations() {
    let mut value = fixture();
    let initial = crate::SignedProviderReconciliation::not_issued(
        crate::provider::provider_operation_ref("target-nonce"),
        "target-nonce",
        "valid",
        NOW,
    );
    value
        .authority
        .reconcile_provider_not_issued(value.transfer.id(), initial, &Verifier)
        .expect("initial cancel");
    for index in 1..=62 {
        let (transfer, nonce) = value.prepare_attempt(index);
        value
            .authority
            .reconcile_provider_not_issued(
                transfer.id(),
                crate::SignedProviderReconciliation::not_issued(
                    crate::provider::provider_operation_ref(&nonce),
                    nonce,
                    "valid",
                    NOW,
                ),
                &Verifier,
            )
            .expect("cancel transient transfer");
    }
    value
        .authority
        .apply_host_device_revocation(&"d".repeat(64), &value.owner, &value.target, 1, 2)
        .expect("revoke former target");
    let replacement = crate::DeviceId::parse("device-target-replacement").expect("target");
    let service = crate::ServiceId::parse("service-a").expect("service");
    value
        .authority
        .store
        .transact(|snapshot| {
            snapshot.devices.insert(
                (value.owner.clone(), replacement.clone()),
                crate::authority_management_transfer_test_support::device(
                    &value.owner,
                    &replacement,
                    &service,
                ),
            );
            Ok(())
        })
        .expect("replacement target");
    value.prepare_attempt_for(replacement, 63);
}
