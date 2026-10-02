#[test]
fn transport_route_is_checked_before_any_historic_recovery() {
    let command = crowsi_credential_authority_contracts::ManagementCommandV2::Cancel {
        operation_id: "operation-a".into(),
        expected_state_revision: 2,
    };
    assert_eq!(
        crate::management_v2_dispatch::command_matches("cancel", &command),
        Ok(())
    );
    assert_eq!(
        crate::management_v2_dispatch::command_matches("source-approve", &command),
        Err(crate::HostError::RequestInvalid)
    );
}
