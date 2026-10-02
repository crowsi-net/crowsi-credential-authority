use std::fs;

use crate::{
    management_v2_journal_fixture::record, management_v2_journal_test_environment::Fixture,
    management_v2_record::ManagementLedgerV2,
};

// CR-11: intent + dual committed heads distinguish crash recovery from one-sided rollback.
#[test]
fn crashes_after_ledger_or_anchor_forward_finish_exact_commit() {
    for with_anchor in [false, true] {
        let fixture = Fixture::new();
        let owner = "psa_owner_0000000000000001";
        let journal = fixture.journal();
        journal
            .insert(record(owner, "device-a", "first"), 1_000)
            .expect("first");
        let next = next_ledger(&fixture, owner);
        stage(&fixture, owner, &next, with_anchor, false);
        let (revision, _) = journal.view(owner).expect("recover committed ledger");
        assert_eq!(revision, next.revision);
    }
}

#[test]
fn post_commit_prune_recovers_but_latest_anchor_deletion_fails_closed() {
    let fixture = Fixture::new();
    let owner = "psa_owner_0000000000000001";
    let journal = fixture.journal();
    journal
        .insert(record(owner, "device-a", "first"), 1_000)
        .expect("first");
    let second = next_ledger(&fixture, owner);
    stage(&fixture, owner, &second, true, true);
    assert_eq!(
        journal.view(owner).expect("prune recovery").0,
        second.revision
    );
    let third = next_ledger(&fixture, owner);
    crate::management_v2_journal_io::write(&fixture.state, &fixture.anchor, owner, &third)
        .expect("third");
    let latest = anchors(&fixture).into_iter().max().expect("latest anchor");
    fs::remove_file(latest).expect("delete committed anchor");
    assert!(journal.view(owner).is_err());
}

fn next_ledger(fixture: &Fixture, owner: &str) -> ManagementLedgerV2 {
    let mut value = crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, owner)
        .expect("current");
    value.revision += 1;
    value
}

fn stage(
    fixture: &Fixture,
    owner: &str,
    next: &ManagementLedgerV2,
    with_anchor: bool,
    remove_intent: bool,
) {
    let prior = crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, owner)
        .expect("prior");
    let wire = serde_json::to_vec(next).expect("wire");
    let digest = crate::host_crypto::digest(&wire);
    crate::management_v2_intent::begin(&fixture.state, owner, &prior, next, &digest)
        .expect("intent");
    crate::management_v2_generation::append(&fixture.state, owner, next, &digest)
        .expect("generation");
    if with_anchor {
        crate::management_v2_anchor::append(&fixture.anchor, owner, next.revision, &digest)
            .expect("anchor");
    }
    if remove_intent {
        crate::management_v2_head::append(&fixture.state, owner, next.revision, &digest)
            .expect("state head");
        crate::management_v2_intent::remove(&fixture.state, owner).expect("intent commit");
    }
}

fn anchors(fixture: &Fixture) -> Vec<std::path::PathBuf> {
    fs::read_dir(&fixture.anchor)
        .expect("anchors")
        .map(|item| item.expect("entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|item| item.to_str())
                .is_some_and(|item| item.starts_with("management-v5-anchor-"))
        })
        .collect()
}
