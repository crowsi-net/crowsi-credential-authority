use crowsi_credential_authority_contracts::{ManagementOperationScopeV2, ManagementOperationState};

use crate::management_v2_journal_fixture::{record, revocation};

#[test]
fn active_resource_overlap_is_rejected_but_terminal_or_disjoint_is_allowed() {
    let mut ledger = crate::management_v2_record::ManagementLedgerV2::empty();
    let first = record("owner-a", "device-a", "first");
    ledger.records.push(first.clone());

    let mut same_credential = record("owner-a", "device-c", "same-credential");
    same_credential.operation.scope = ManagementOperationScopeV2::DeviceTransfer {
        target_device_ref: "device-d".into(),
        credential_refs: vec!["credential-a".into()],
        expected_source_device_revocation_epoch: 1,
    };
    assert!(!crate::management_v2_operation_conflict::available(
        &ledger,
        &same_credential
    ));
    assert!(!crate::management_v2_operation_conflict::available(
        &ledger,
        &revocation("owner-a", "device-c", "revoke-target")
    ));

    let mut reserves_rotation_target = revocation("owner-a", "device-c", "rotation-target");
    reserves_rotation_target
        .revocation_saga
        .as_mut()
        .expect("saga")
        .rotations
        .push(rotation("device-d"));
    let mut transfer_to_reserved = record("owner-a", "device-e", "reserved-target");
    transfer_to_reserved.operation.scope = ManagementOperationScopeV2::DeviceTransfer {
        target_device_ref: "device-d".into(),
        credential_refs: vec!["credential-c".into()],
        expected_source_device_revocation_epoch: 1,
    };
    let mut reservation_ledger = crate::management_v2_record::ManagementLedgerV2::empty();
    reservation_ledger.records.push(reserves_rotation_target);
    assert!(!crate::management_v2_operation_conflict::available(
        &reservation_ledger,
        &transfer_to_reserved
    ));

    let mut disjoint = record("owner-a", "device-c", "disjoint");
    disjoint.operation.scope = ManagementOperationScopeV2::DeviceTransfer {
        target_device_ref: "device-d".into(),
        credential_refs: vec!["credential-b".into()],
        expected_source_device_revocation_epoch: 1,
    };
    assert!(crate::management_v2_operation_conflict::available(
        &ledger, &disjoint
    ));

    ledger.records[0].operation.state = ManagementOperationState::Completed;
    assert!(crate::management_v2_operation_conflict::available(
        &ledger,
        &same_credential
    ));
}

#[test]
fn irreversible_finalizer_is_reserved_in_both_race_orders() {
    let fixture = crate::management_v2_journal_test_environment::Fixture::new();
    let value = crate::management_v2_revocation_finalization_tests::revocation_case();
    crate::management_v2_revocation_finalization_tests::persist(&fixture, &value.record);
    fixture
        .journal()
        .accept_execution_reservation(
            &value.reserve,
            crate::management_v2_revocation_finalization_tests::DEVICE,
            &crate::management_v2_execution_cancellation_tests::test_config(7),
            &[],
            crate::management_v2_revocation_finalization_tests::NOW + 1,
        )
        .expect("execution reservation");
    let mut reserved = fixture
        .journal()
        .record(
            crate::management_v2_revocation_finalization_tests::OWNER,
            &value.record.operation.operation_id,
        )
        .expect("reserved record");
    reserved
        .revocation_finalization
        .as_mut()
        .expect("finalization")
        .execution_reservation
        .as_mut()
        .expect("reservation")
        .reservation
        .finalizer_device_ref = "device-finalizer".into();
    let mut revoke_finalizer = revocation(
        crate::management_v2_revocation_finalization_tests::OWNER,
        "device-finalizer",
        "revoke-finalizer",
    );
    let ManagementOperationScopeV2::DeviceRevocation {
        target_device_ref, ..
    } = &mut revoke_finalizer.operation.scope
    else {
        unreachable!()
    };
    *target_device_ref = "device-finalizer".into();

    let mut after = crate::management_v2_record::ManagementLedgerV2::empty();
    after.records.push(reserved.clone());
    assert!(!crate::management_v2_operation_conflict::available(
        &after,
        &revoke_finalizer,
    ));

    let mut before = crate::management_v2_record::ManagementLedgerV2::empty();
    before.records.push(reserved.clone());
    before.records.push(revoke_finalizer);
    assert!(!crate::management_v2_operation_conflict::available_replacement(&before, &reserved,));
}

fn rotation(target: &str) -> crate::management_v2_record::RevocationRotationV2 {
    crate::management_v2_record::RevocationRotationV2 {
        credential_ref: "credential-x".into(),
        target_device_ref: target.into(),
        target_binding: None,
        provider_request_id: "request-a".into(),
        provider_operation_ref: "provider-a".into(),
        provider_nonce: "nonce-a".into(),
        attempt_number: 1,
        reconcile_sequence: 0,
        provider_reconcile_request_id: None,
        attempted: false,
        provider_acceptance: None,
        prior_acceptances: Vec::new(),
        prior_acceptance_count: 0,
        prior_acceptance_digest_sha256: crate::management_v2_provider_progress::empty_digest(
            "rotation",
        ),
        authority_applied: false,
    }
}
