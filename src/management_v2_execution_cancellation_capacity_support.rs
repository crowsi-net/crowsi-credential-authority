fn reserved_bytes(fixture: &crate::management_v2_journal_test_environment::Fixture) -> u64 {
    fixture
        .journal()
        .record(OWNER, &revocation_case().record.operation.operation_id)
        .expect("record")
        .revocation_finalization
        .expect("finalization")
        .cancellation_recovery_reservation_bytes
}

fn cancellation_high_water(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
) -> u64 {
    let ledger = crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, OWNER)
        .expect("ledger");
    crate::management_v2_journal_cancel_capacity::high_water(&ledger).expect("capacity")
}
