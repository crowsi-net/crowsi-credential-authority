#[test]
fn terminal_churn_is_bounded_and_reserves_recovery_progress() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let first = seed_terminal_boundary(&fixture);
    assert!(
        journal
            .insert(record("owner-a", "device-a", "overflow"), NOW)
            .is_err(),
        "bounded per-source churn must stop at the exact durable boundary"
    );
    let recovery = journal
        .insert(revocation("owner-a", "device-c", "recovery"), NOW)
        .expect("reserved recovery progress");
    assert_eq!(recovery.operation.source_device_ref, "device-c");
    let terminal = journal
        .insert(first, NOW)
        .expect("terminal retry");
    assert_eq!(
        terminal.operation.state,
        ManagementOperationState::Completed
    );
}

fn seed_terminal_boundary(fixture: &Fixture) -> crate::management_v2_record::ManagementRecordV2 {
    let mut ledger = crate::management_v2_journal_io::read(
        &fixture.state,
        &fixture.anchor,
        "owner-a",
    )
    .expect("empty ledger");
    let first = completed(record("owner-a", "device-a", "tombstone-0"));
    for index in 0..128 {
        let value = completed(record(
            "owner-a",
            "device-a",
            &format!("tombstone-{index}"),
        ));
        ledger.tombstones.push(
            crate::management_v2_record::ManagementTombstoneV2::from_record(&value)
                .expect("valid terminal tombstone"),
        );
    }
    for index in 0..79 {
        ledger.records.push(completed(record(
            "owner-a",
            "device-a",
            &format!("terminal-{index}"),
        )));
    }
    ledger.revision += 1;
    crate::management_v2_journal_io::write(
        &fixture.state,
        &fixture.anchor,
        "owner-a",
        &ledger,
    )
    .expect("terminal boundary");
    first
}

fn completed(
    mut value: crate::management_v2_record::ManagementRecordV2,
) -> crate::management_v2_record::ManagementRecordV2 {
    value.operation.state = ManagementOperationState::Completed;
    value.operation.state_revision = 2;
    value
}

#[test]
fn owner_and_source_quotas_do_not_let_a_block_b_or_c() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    for index in 0..16 {
        journal
            .insert(
                record("owner-a", "device-a", &format!("active-{index}")),
                NOW,
            )
            .expect("a quota");
    }
    assert!(
        journal
            .insert(record("owner-a", "device-a", "overflow"), NOW)
            .is_err()
    );
    journal
        .insert(revocation("owner-a", "device-c", "control"), NOW)
        .expect("same-owner recovery reserve");
    journal
        .insert(record("owner-b", "device-b", "independent"), NOW)
        .expect("other owner isolated");
}
