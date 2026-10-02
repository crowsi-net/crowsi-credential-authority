#[test]
fn exact_final_is_journaled_before_side_effect_and_uses_pinned_old_key() {
    let fixture = crate::management_v2_journal_test_environment::Fixture::new();
    let value = revocation_case();
    persist(&fixture, &value.record);
    let finalize = reserve_and_finalize(&fixture, &value);
    let journal = fixture.journal();
    journal
        .expire_due(OWNER, 2, NOW + 301)
        .expect("restart after evidence expiry");

    let mut wrong = finalize.clone();
    wrong.final_revoke_exchange.response.signature = "00".repeat(64);
    assert!(journal.accept_revocation_final(&wrong, DEVICE).is_err());
    assert_eq!(
        journal
            .record(OWNER, &value.record.operation.operation_id)
            .expect("unchanged")
            .operation
            .state,
        ManagementOperationState::RevocationExecutionReserved
    );

    let mut rotated_key = finalize.clone();
    rotated_key.final_revoke_exchange.response.key_id = "rotated-response-key".into();
    rotated_key.final_revoke_exchange.response.config_generation = 3;
    rotated_key.final_revoke_exchange.response.signature = hex::encode(
        crate::gateway_peer_response_identity::key(6)
            .sign(
                &canonical_response(&rotated_key.final_revoke_exchange.response)
                    .expect("rotated response canonical"),
            )
            .to_bytes(),
    );
    assert!(
        journal
            .accept_revocation_final(&rotated_key, DEVICE)
            .is_err()
    );
    assert_eq!(
        journal
            .record(OWNER, &value.record.operation.operation_id)
            .expect("rotated key leaves acceptance pending")
            .operation
            .state,
        ManagementOperationState::RevocationExecutionReserved
    );

    let accepted = journal
        .accept_revocation_final(&finalize, DEVICE)
        .expect("pinned historic final");
    let crate::management_v2_journal_finalization::FinalizationEntry::Record(record) = accepted
    else {
        panic!("record")
    };
    assert_eq!(record.operation.state, ManagementOperationState::Unknown);
    assert!(!crate::management_v2_lookup_policy::allowed(
        crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1::Cancel,
        &record,
        DEVICE,
        &record.prepared.source_session_ref,
    ));
    assert!(
        !record
            .revocation_saga
            .as_ref()
            .expect("saga")
            .local_revocation_applied
    );
    let acceptance = record.revocation_finalization.as_ref().expect("acceptance");
    assert_eq!(
        acceptance.final_revoke_exchange.as_ref(),
        Some(&finalize.final_revoke_exchange)
    );

    let reopened = fixture.journal();
    reopened
        .accept_revocation_final(&finalize, DEVICE)
        .expect("exact restart replay");
}
