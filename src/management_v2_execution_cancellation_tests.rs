include!("management_v2_execution_cancellation_test_support.rs");
include!("management_v2_execution_cancellation_capacity_tests.rs");

#[test]
fn cancelled_pre_final_cleanup_survives_restart_expiry_and_management_key_rotation() {
    let fixture = crate::management_v2_journal_test_environment::Fixture::new();
    let value = revocation_case();
    persist(&fixture, &value.record);
    let cancel = cancel_envelope(&value);
    handler(&fixture, 7)
        .handle(&transport("cancel", &cancel), NOW + 1)
        .expect("browser Cancel commits slot and receipt");
    let cancel_high_water = cancellation_high_water(&fixture);
    assert!(reserved_bytes(&fixture) > 0);
    assert!(!terminal_receipt_evictable(&fixture));

    let cancel_request = cancellation_request(&value, cancel);
    let mut wrong_peer = transport("revocation-execution-cancel", &cancel_request);
    wrong_peer.peer.device_id = "device-substituted".into();
    assert!(
        handler(&fixture, 7)
            .cancel_pending_revocation_execution(&wrong_peer, NOW + 2)
            .is_err()
    );
    let request = transport("revocation-execution-cancel", &cancel_request);
    let mut wrong_begin = cancel_request.clone();
    wrong_begin.begin_exchange.response.signature = "00".repeat(64);
    assert!(
        handler(&fixture, 7)
            .cancel_pending_revocation_execution(
                &transport("revocation-execution-cancel", &wrong_begin),
                NOW + 2,
            )
            .is_err()
    );
    let lost = handler(&fixture, 7)
        .cancel_pending_revocation_execution(&request, NOW + 2)
        .expect("central cancellation acceptance before response loss");
    let accepted = decode_cancellation(&lost);
    assert!(reserved_bytes(&fixture) > 0);
    assert!(cancellation_high_water(&fixture) <= cancel_high_water);

    let restarted = handler(&fixture, 8);
    let recovered = restarted
        .cancel_pending_revocation_execution(&request, NOW + 301)
        .expect("fresh outer after restart and key rotation");
    let recovered = decode_cancellation(&recovered);
    assert_eq!(recovered.cancellation_id, accepted.cancellation_id);
    assert_eq!(recovered.token, accepted.token);
    assert_ne!(recovered.signature, accepted.signature);
    let inactive = inactive_gateway(&fixture);
    crate::gateway_peer_response::apply(
        &inactive,
        &test_config(8).document,
        &request,
        &serde_json::to_vec(&recovered).expect("recovered cancellation wire"),
        NOW + 301,
    )
    .expect("gateway accepts current outer and immutable root cancellation");

    let cancelled_exchange = cancelled_exchange(&recovered, NOW + 302);
    let cleanup_request = cleanup_request(cancel_request, recovered, cancelled_exchange);
    let mut substituted = cleanup_request.clone();
    substituted.cancel_pending_exchange.response.signature = "00".repeat(64);
    assert!(
        restarted
            .acknowledge_pending_revocation_cancellation(
                &transport("revocation-execution-cancel-finalize", &substituted),
                NOW + 303,
            )
            .is_err()
    );
    let mut substituted_root = cleanup_request.clone();
    substituted_root.cancellation.token.signature = "00".repeat(64);
    assert!(
        restarted
            .acknowledge_pending_revocation_cancellation(
                &transport("revocation-execution-cancel-finalize", &substituted_root,),
                NOW + 303,
            )
            .is_err()
    );
    assert!(slot(&fixture));

    let cleanup_transport = transport("revocation-execution-cancel-finalize", &cleanup_request);
    let lost = restarted
        .acknowledge_pending_revocation_cancellation(&cleanup_transport, NOW + 303)
        .expect("cleanup root proof accepted before response loss");
    let accepted_cleanup = decode_cleanup(&lost);
    assert!(slot(&fixture));
    assert!(reserved_bytes(&fixture) > 0);
    assert!(cancellation_high_water(&fixture) <= cancel_high_water);
    assert!(!terminal_receipt_evictable(&fixture));

    let recovered = handler(&fixture, 9)
        .acknowledge_pending_revocation_cancellation(&cleanup_transport, NOW + 604)
        .expect("cleanup ack exact recovery");
    let recovered_cleanup = decode_cleanup(&recovered);
    assert_eq!(recovered_cleanup.cleanup_id, accepted_cleanup.cleanup_id);
    assert_eq!(recovered_cleanup.token, accepted_cleanup.token);
    assert_ne!(recovered_cleanup.signature, accepted_cleanup.signature);
    crate::gateway_peer_response::apply(
        &inactive,
        &test_config(9).document,
        &cleanup_transport,
        &serde_json::to_vec(&recovered_cleanup).expect("recovered cleanup wire"),
        NOW + 604,
    )
    .expect("gateway accepts current outer and immutable cleanup root");
    complete_cleanup_delivery(&fixture, &inactive, cleanup_request, recovered_cleanup);
}
