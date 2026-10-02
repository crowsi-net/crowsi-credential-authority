#[test]
fn evidence_set_is_atomic_expiring_bounded_and_durable() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let first = journal
        .insert(record("owner-a", "device-a", "one"), NOW)
        .expect("insert");
    let mut advanced = first.clone();
    advanced.operation.state = ManagementOperationState::AwaitingTarget;
    advanced.operation.state_revision = 2;
    let invalid = [
        use_of("proof-a", NOW + 10, 'a'),
        use_of("proof-b", NOW, 'a'),
    ];
    assert!(
        journal
            .replace_consuming(1, advanced.clone(), &invalid, NOW)
            .is_err()
    );
    assert_eq!(
        journal
            .record("owner-a", &first.operation.operation_id)
            .expect("unchanged")
            .operation
            .state_revision,
        1
    );

    let second = journal
        .insert(record("owner-a", "device-a", "two"), NOW)
        .expect("second");
    let mut next = second.clone();
    next.operation.state = ManagementOperationState::AwaitingTarget;
    next.operation.state_revision = 2;
    journal
        .replace_consuming(1, next, &[use_of("proof-a", NOW + 10, 'a')], NOW)
        .expect("failed set consumed no prefix");

    let third = journal
        .insert(record("owner-a", "device-a", "three"), NOW)
        .expect("third");
    let mut replay = third.clone();
    replay.operation.state_revision = 2;
    assert!(
        journal
            .replace_consuming(1, replay, &[use_of("proof-a", NOW + 10, 'b')], NOW)
            .is_err()
    );
    let mut too_long = third;
    too_long.operation.state_revision = 2;
    assert!(
        journal
            .replace_consuming(1, too_long, &[use_of("proof-c", NOW + 121, 'c')], NOW)
            .is_err()
    );
}

#[test]
fn universal_semantic_key_allows_only_the_exact_same_binding() {
    let mut ledger = crate::management_v2_record::ManagementLedgerV2::empty();
    let exact = [use_of("shared-status-nonce", NOW + 10, 'a')];
    crate::management_v2_evidence_use::consume(&mut ledger, &exact, NOW).expect("first use");
    crate::management_v2_evidence_use::consume(&mut ledger, &exact, NOW).expect("exact retry");
    assert_eq!(ledger.consumed_evidence.len(), 1);
    assert_eq!(
        crate::management_v2_evidence_use::consume(
            &mut ledger,
            &[use_of("shared-status-nonce", NOW + 10, 'b')],
            NOW,
        ),
        Err(crate::HostError::StateInvalid)
    );
}

#[test]
fn semantic_ids_are_universal_across_roles_and_same_binding_coalesces() {
    let mut ledger = crate::management_v2_record::ManagementLedgerV2::empty();
    let same = [
        use_of_kind("identity_assertion_nonce", "same-nonce", NOW + 5, 'a'),
        use_of_kind("current_status_nonce", "same-nonce", NOW + 10, 'a'),
    ];
    crate::management_v2_evidence_use::consume(&mut ledger, &same, NOW).expect("coalesced pair");
    assert_eq!(ledger.consumed_evidence.len(), 1);
    assert_eq!(ledger.consumed_evidence[0].expires_at_epoch_s, NOW + 10);
    assert_eq!(
        crate::management_v2_evidence_use::consume(
            &mut ledger,
            &[use_of_kind(
                "revocation_approval_proof",
                "same-nonce",
                NOW + 10,
                'b'
            )],
            NOW,
        ),
        Err(crate::HostError::StateInvalid)
    );
}
