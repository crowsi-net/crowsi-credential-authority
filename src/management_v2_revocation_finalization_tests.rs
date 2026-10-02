include!("management_v2_revocation_finalization_test_support.rs");

#[test]
fn pre_final_acceptance_is_exact_durable_and_not_lazily_expired() {
    let fixture = crate::management_v2_journal_test_environment::Fixture::new();
    let value = revocation_case();
    persist(&fixture, &value.record);
    let journal = fixture.journal();

    let (_, stored) = journal
        .revocation_pre_final_view(&value.envelope, DEVICE, NOW + 31)
        .expect("view")
        .expect("accepted");
    assert_eq!(
        stored.operation.state,
        ManagementOperationState::AwaitingRevocationFinal
    );
    assert_eq!(
        stored
            .revocation_finalization
            .as_ref()
            .expect("acceptance")
            .pre_final_snapshot_revision,
        2
    );
    let mut disjoint = crate::management_v2_journal_fixture::record(OWNER, "device-x", "disjoint");
    disjoint.authority_config_generation = 2;
    journal
        .insert(disjoint, NOW)
        .expect("disjoint owner mutation");
    let (advanced_revision, replay) = journal
        .revocation_pre_final_view(&value.envelope, DEVICE, NOW + 31)
        .expect("advanced view")
        .expect("accepted after head advance");
    assert!(advanced_revision > 2);
    assert_eq!(
        replay
            .revocation_finalization
            .as_ref()
            .expect("acceptance")
            .pre_final_snapshot_revision,
        2
    );

    let mut substitution = value.envelope.clone();
    substitution.browser_request.request_id = "substituted-request".into();
    assert!(
        journal
            .revocation_pre_final_view(&substitution, DEVICE, NOW + 31)
            .expect("closed miss")
            .is_none()
    );
    assert!(
        journal
            .revocation_pre_final_view(&value.envelope, "device-substituted", NOW + 31)
            .expect("peer miss")
            .is_none()
    );

    journal
        .expire_due(OWNER, 2, NOW + 301)
        .expect("lazy expiry sweep");
    assert!(
        journal
            .revocation_pre_final_view(&value.envelope, DEVICE, NOW + 301)
            .expect("expired begin")
            .is_none()
    );
    let recovered = journal
        .record(OWNER, &value.record.operation.operation_id)
        .expect("awaiting final survives");
    assert_eq!(recovered.operation.state_revision, 2);
    assert!(crate::management_v2_lookup_policy::allowed(
        crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1::Cancel,
        &recovered,
        DEVICE,
        &recovered.prepared.source_session_ref,
    ));
    assert!(!crate::management_v2_lookup_policy::allowed(
        crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1::Cancel,
        &recovered,
        DEVICE,
        "rotated-session",
    ));
    let mut cancelled = recovered;
    cancelled.operation.state = ManagementOperationState::Cancelled;
    cancelled.operation.state_revision = 3;
    cancelled.operation.actor = crate::management_v2_state::none_actor();
    cancelled.operation.reason =
        Some(crowsi_credential_authority_contracts::ManagementReasonCode::OperationCancelled);
    cancelled.operation.reconcile_digest = None;
    cancelled
        .revocation_finalization
        .as_mut()
        .expect("pre-final acceptance")
        .cancellation_slot_reserved = true;
    assert!(crate::management_v2_revocation_finalization_acceptance::record(&cancelled));
}

include!("management_v2_revocation_finalization_restart_tests.rs");
