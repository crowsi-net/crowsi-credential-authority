fn compact_cancelled_record_to_tombstone(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
) {
    let mut ledger = crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, OWNER)
        .expect("ledger");
    let operation = revocation_case().record.operation.operation_id;
    let base = ledger
        .records
        .iter()
        .find(|item| item.operation.operation_id == operation)
        .expect("cancelled record")
        .clone();
    for index in 0..79_u64 {
        let mut dummy = base.clone();
        dummy.operation.operation_id = format!("{index:064x}");
        dummy.operation.created_at_epoch_s = base.operation.created_at_epoch_s + index + 1;
        ledger.records.push(dummy);
    }
    crate::management_v2_journal_policy::compact(&mut ledger, NOW + 700).expect("compact");
    ledger
        .records
        .retain(|item| item.operation.operation_id == operation);
    assert!(
        ledger.records.is_empty(),
        "target record moved to tombstone"
    );
    assert!(
        ledger
            .tombstones
            .iter()
            .any(|item| item.operation.operation_id == operation)
    );
    ledger.revision += 1;
    crate::management_v2_journal_io::write(&fixture.state, &fixture.anchor, OWNER, &ledger)
        .expect("persist compacted tombstone");
}
