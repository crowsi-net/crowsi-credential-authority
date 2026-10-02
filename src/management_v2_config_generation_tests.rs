use crate::{
    HostError,
    management_v2_journal_fixture::{Fixture, NOW, record},
    management_v2_journal_test_environment::identity_exchange,
};

#[test]
fn owner_generation_high_water_rejects_downgrade_after_reopen() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let mut stored = record("owner-a", "device-a", "generation-a");
    stored.authority_config_generation = 10;
    journal.insert(stored.clone(), NOW).expect("generation 10");
    drop(journal);

    let reopened = fixture.journal();
    assert_eq!(reopened.generation_head("owner-a"), Ok(10));
    let mut old = identity_exchange("device-a");
    old.response.config_generation = 9;
    assert_eq!(
        crate::management_v2_config_generation::record(&reopened, &stored, &[&old]),
        Err(HostError::EvidenceInvalid)
    );
}

#[test]
fn every_nested_exchange_must_meet_the_current_generation_floor() {
    let mut current = identity_exchange("device-a");
    current.response.config_generation = 10;
    let mut old = identity_exchange("device-a");
    old.response.config_generation = 9;
    assert_eq!(
        crate::management_v2_config_generation::advance(10, &[&current]),
        Ok(10)
    );
    assert_eq!(
        crate::management_v2_config_generation::advance(10, &[&current, &old]),
        Err(HostError::EvidenceInvalid)
    );
}

#[test]
fn passive_and_lookup_views_reject_identity_below_owner_generation_head() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let mut stored = record("owner-a", "device-a", "generation-view");
    stored.authority_config_generation = 11;
    journal.insert(stored, NOW).expect("generation 11");
    assert_eq!(
        journal.current_view("owner-a", 10),
        Err(HostError::EvidenceInvalid)
    );
    assert!(journal.current_view("owner-a", 11).is_ok());
}
