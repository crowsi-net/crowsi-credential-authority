#[test]
fn ledger_v17_reopen_validation_rejects_pre_reservation_schema() {
    let mut ledger = crate::management_v2_record::ManagementLedgerV2::empty();
    crate::management_v2_journal_io::validate(&ledger, OWNER, ledger.revision).expect("v17 ledger");
    ledger.schema = "crowsi://credential-authority/management-ledger/v16".into();
    assert!(crate::management_v2_journal_io::validate(&ledger, OWNER, ledger.revision).is_err());

    let mut ledger = crate::management_v2_record::ManagementLedgerV2::empty();
    ledger.records.push(revocation_case().record);
    let mut wire = serde_json::to_value(ledger).expect("ledger JSON");
    wire["records"][0]["revocation_finalization"]
        .as_object_mut()
        .expect("acceptance")
        .remove("cancellation_recovery_reservation_bytes");
    assert!(
        serde_json::from_value::<crate::management_v2_record::ManagementLedgerV2>(wire).is_err()
    );
}

#[test]
fn full_cancel_cleanup_quota_rejects_before_terminal_transition() {
    let mut ledger = crate::management_v2_record::ManagementLedgerV2::empty();
    for index in 0..4 {
        let mut record = revocation_case().record;
        record.operation.operation_id = format!("reserved-cancel-{index}");
        record.operation.state = ManagementOperationState::Cancelled;
        record
            .revocation_finalization
            .as_mut()
            .expect("finalization")
            .cancellation_slot_reserved = true;
        ledger.records.push(record);
    }
    let current = revocation_case().record;
    let mut cancelled = current.clone();
    cancelled.operation.state = ManagementOperationState::Cancelled;
    assert!(
        crate::management_v2_journal_cancel_slot::reserve(
            std::path::Path::new("/unread-because-owner-quota-is-full"),
            &ledger,
            &current,
            &mut cancelled,
        )
        .is_err()
    );
    assert!(
        !cancelled
            .revocation_finalization
            .expect("finalization")
            .cancellation_slot_reserved
    );
}
