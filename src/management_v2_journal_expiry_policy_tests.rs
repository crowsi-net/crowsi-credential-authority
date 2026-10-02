#[test]
fn expired_uv_waiters_release_quota_durably_but_unknown_remains_recoverable() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let mut unknown = revocation("owner-a", "device-c", "unknown");
    unknown.operation.state = ManagementOperationState::Unknown;
    unknown.operation.expires_at_epoch_s = NOW + 1;
    journal.insert(unknown.clone(), NOW).expect("unknown");
    for index in 0..16 {
        let mut waiting = record("owner-a", "device-a", &format!("waiting-{index}"));
        waiting.operation.state = ManagementOperationState::AwaitingTargetUv;
        waiting.operation.expires_at_epoch_s = NOW + 1;
        journal.insert(waiting, NOW).expect("source quota");
    }

    journal.expire_due("owner-a", 1, NOW + 1).expect("expire");
    let reopened = fixture.journal();
    reopened
        .insert(record("owner-a", "device-a", "after-expiry"), NOW + 1)
        .expect("expired operations release active source quota");
    assert_eq!(
        reopened
            .record("owner-a", &unknown.operation.operation_id)
            .expect("unknown retained")
            .operation
            .state,
        ManagementOperationState::Unknown
    );
    let (_, records) = reopened.view("owner-a").expect("view");
    assert_eq!(
        records
            .iter()
            .filter(|value| value.operation.state == ManagementOperationState::Expired)
            .count(),
        16
    );
    assert_eq!(
        records
            .iter()
            .filter(|value| {
                value.operation.state == ManagementOperationState::Expired
                    && value.operation.reason
                        == Some(
                            crowsi_credential_authority_contracts::ManagementReasonCode::OperationExpired,
                        )
                    && value.operation.state_revision == 2
            })
            .count(),
        16
    );
}

#[test]
fn expiry_commit_advances_the_owner_identity_generation_head() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let mut waiting = record("owner-generation", "device-a", "ratchet");
    waiting.authority_config_generation = 10;
    waiting.operation.state = ManagementOperationState::AwaitingApprovalUv;
    waiting.operation.expires_at_epoch_s = NOW + 1;
    let operation_id = waiting.operation.operation_id.clone();
    journal.insert(waiting, NOW).expect("generation ten");

    journal
        .expire_due("owner-generation", 11, NOW + 1)
        .expect("generation eleven expiry");
    let reopened = fixture.journal();
    assert!(reopened.current_view("owner-generation", 10).is_err());
    assert!(reopened.current_view("owner-generation", 11).is_ok());
    assert_eq!(
        reopened
            .record("owner-generation", &operation_id)
            .expect("expired record")
            .authority_config_generation,
        11
    );
}
