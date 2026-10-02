include!("management_v2_cancel_recovery_test_support.rs");

#[test]
fn cancelled_receipt_recovers_after_identity_expiry_restart_and_tombstone() {
    let accepted = accepted_cancel();
    let fixture = &accepted.fixture;
    let envelope = &accepted.envelope;

    assert!(
        fixture
            .journal()
            .cancel_recovery_view(envelope, "device-a", NOW + 31)
            .expect("identity-expired recovery")
            .is_some()
    );
    assert!(
        fixture
            .journal()
            .cancel_recovery_view(envelope, "device-a", NOW + 301)
            .expect("historic restart")
            .is_some()
    );
    assert!(
        fixture
            .journal()
            .cancel_recovery_view(envelope, "device-substituted", NOW + 301)
            .is_err()
    );

    move_to_tombstone(fixture, &accepted.cancelled);
    compact_after_long_stop(fixture);
    assert!(
        fixture
            .journal()
            .cancel_recovery_view(envelope, "device-a", NOW + 601)
            .expect("tombstone restart")
            .is_some()
    );
    let mut changed = envelope.clone();
    changed.browser_request.request_id = "cancel-substituted".into();
    assert!(
        fixture
            .journal()
            .cancel_recovery_view(&changed, "device-a", NOW + 601)
            .expect("unaccepted substitution")
            .is_none()
    );
}

include!("management_v2_cancel_recovery_response_tests.rs");
