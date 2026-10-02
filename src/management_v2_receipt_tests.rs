use crate::{
    management_v2_journal_fixture::{Fixture, NOW, record},
    management_v2_receipt_test_support::{digest, evidence, receipt},
};

#[test]
fn mutation_response_state_evidence_and_exact_bytes_commit_atomically() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let mut value = record("owner-receipt", "device-a", "mutation");
    value.authority_config_generation = 10;
    let response = receipt(&value, 'a', 'b', 2, false, NOW + 30);
    let expected = crate::management_v2_receipt::wire(&response).expect("wire");
    let binding = digest('a');
    let (_, returned) = journal
        .insert_consuming_response(
            value.clone(),
            &[evidence("shared-status", &binding, NOW + 20)],
            response,
            NOW,
        )
        .expect("atomic response");
    assert_eq!(returned, expected);
    assert_eq!(
        fixture
            .journal()
            .exact_response("owner-receipt", &digest('a'), &digest('b'), 10, NOW + 1)
            .expect("exact"),
        Some(expected.clone())
    );

    let mut expiring = record("owner-receipt", "device-c", "generation");
    expiring.authority_config_generation = 10;
    expiring.operation.expires_at_epoch_s = NOW + 1;
    journal.insert(expiring, NOW).expect("head ten");
    journal
        .expire_due("owner-receipt", 11, NOW + 1)
        .expect("head eleven");
    assert!(
        journal
            .exact_response("owner-receipt", &digest('a'), &digest('b'), 10, NOW + 1)
            .is_err()
    );
    assert_eq!(
        journal
            .exact_response("owner-receipt", &digest('a'), &digest('b'), 11, NOW + 1)
            .expect("forward generation"),
        Some(expected)
    );
    assert!(
        journal
            .exact_response("owner-receipt", &digest('a'), &digest('b'), 11, NOW + 30)
            .is_err()
    );
}

#[test]
fn read_receipt_is_revision_current_and_blocks_cross_route_nonce_reuse() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let value = record("owner-read", "device-a", "read");
    let first = receipt(&value, 'c', 'd', 2, true, NOW + 30);
    let first_wire = journal
        .commit_read_response(
            "owner-read",
            1,
            1,
            &[evidence("read-status", &digest('c'), NOW + 120)],
            first,
            NOW,
        )
        .expect("read receipt");
    assert_eq!(
        journal
            .exact_response("owner-read", &digest('c'), &digest('d'), 1, NOW + 1)
            .expect("exact"),
        Some(first_wire)
    );

    let second = receipt(&value, 'e', 'f', 3, true, NOW + 60);
    assert!(
        journal
            .commit_read_response(
                "owner-read",
                2,
                1,
                &[evidence("read-status", &digest('e'), NOW + 120)],
                second,
                NOW + 31,
            )
            .is_err()
    );
    journal.insert(value, NOW).expect("later state change");
    assert!(
        journal
            .exact_response("owner-read", &digest('c'), &digest('d'), 1, NOW + 1)
            .is_err()
    );
}

#[test]
fn pending_status_view_keeps_recent_terminal_convergence_visible() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let active = record("owner-status", "device-a", "active");
    let terminal_id = record("owner-status", "device-a", "terminal")
        .operation
        .operation_id;
    let mut terminal = record("owner-status", "device-a", "terminal");
    terminal.operation.state =
        crowsi_credential_authority_contracts::ManagementOperationState::Completed;
    terminal.operation.actor = crate::management_v2_state::none_actor();
    journal.insert(active, NOW).expect("active");
    journal.insert(terminal, NOW).expect("terminal");

    let (_, operations) = journal
        .current_operations("owner-status", "service-a", 1)
        .expect("operation status");
    assert_eq!(operations.len(), 2);
    assert!(operations.iter().any(|item| {
        item.operation_id == terminal_id
            && item.state
                == crowsi_credential_authority_contracts::ManagementOperationState::Completed
    }));
}
