use crate::management_v2_journal_test_environment::Fixture;

#[test]
fn compromised_device_cannot_exhaust_sibling_transport_witness_or_mutation_evidence() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let owner = "psa_owner_0000000000000001";
    for value in 0..256_u64 {
        journal
            .consume_transport_replay(owner, "device-a", &format!("{value:064x}"), 1_300, 1_000)
            .unwrap_or_else(|error| panic!("A slot {value}: {error}"));
    }
    assert!(
        journal
            .consume_transport_replay(owner, "device-a", &"f".repeat(64), 1_300, 1_000)
            .is_err()
    );
    journal
        .consume_transport_replay(owner, "device-b", &"b".repeat(64), 1_300, 1_000)
        .expect("B reserve remains available");
    let ledger = crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, owner)
        .expect("ledger");
    assert_eq!(ledger.transport_replays.len(), 257);
    assert!(ledger.consumed_evidence.is_empty());
}
