fn complete_cleanup_delivery(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
    inactive: &crate::gateway_peer_status::GatewayPeerStatus,
    cancel_finalize: Box<EndpointRevocationExecutionCancelFinalizeRequestV1>,
    cleanup: Box<
        crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupV1,
    >,
) {
    let (request, accepted) = accept_cleanup_delivery(fixture, cancel_finalize, cleanup);
    recover_cleanup_delivery(fixture, inactive, request, accepted);
}

fn accept_cleanup_delivery(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
    cancel_finalize: Box<EndpointRevocationExecutionCancelFinalizeRequestV1>,
    cleanup: Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupV1>,
) -> (
    Box<EndpointRevocationExecutionCancelCleanupCompleteRequestV1>,
    Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupCompleteV1>,
){
    let acknowledgement = acknowledged_exchange(&cleanup, NOW + 605, "identity-response-key", 5, 2);
    let request = cleanup_complete_request(cancel_finalize, cleanup, acknowledgement);
    let mut wrong_peer = transport(CLEANUP_COMPLETE_ROUTE, &request);
    wrong_peer.peer.device_id = "device-substituted".into();
    assert!(
        handler(fixture, 9)
            .complete_pending_revocation_cancellation_cleanup(&wrong_peer, NOW + 606)
            .is_err()
    );
    let mut wrong_ack = request.clone();
    wrong_ack.acknowledge_exchange.response.signature = "00".repeat(64);
    assert!(
        handler(fixture, 9)
            .complete_pending_revocation_cancellation_cleanup(
                &transport(CLEANUP_COMPLETE_ROUTE, &wrong_ack),
                NOW + 606,
            )
            .is_err()
    );
    let mut wrong_root = request.clone();
    wrong_root.cleanup.token.signature = "00".repeat(64);
    assert!(
        handler(fixture, 9)
            .complete_pending_revocation_cancellation_cleanup(
                &transport(CLEANUP_COMPLETE_ROUTE, &wrong_root),
                NOW + 606,
            )
            .is_err()
    );
    let transport_request = transport(CLEANUP_COMPLETE_ROUTE, &request);
    let lost = handler(fixture, 9)
        .complete_pending_revocation_cancellation_cleanup(&transport_request, NOW + 606)
        .expect("cleanup delivery commits before response loss");
    let accepted = Box::new(
        crowsi_credential_authority_contracts::decode_endpoint_revocation_execution_cancellation_cleanup_complete_strict(&lost)
            .expect("cleanup delivery proof"),
    );
    assert!(!slot(fixture));
    assert_eq!(reserved_bytes(fixture), 0);
    assert!(terminal_receipt_evictable(fixture));
    compact_cancelled_record_to_tombstone(fixture);
    (request, accepted)
}

fn recover_cleanup_delivery(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
    inactive: &crate::gateway_peer_status::GatewayPeerStatus,
    request: Box<EndpointRevocationExecutionCancelCleanupCompleteRequestV1>,
    accepted: Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupCompleteV1>,
) {
    let rotated = handler_with_identity(fixture, 10, "identity-response-key-rotated", 13, 3);
    let fresh_cleanup = rotated
        .acknowledge_pending_revocation_cancellation(
            &transport(
                "revocation-execution-cancel-finalize",
                &request.cancel_finalize_request,
            ),
            NOW + 905,
        )
        .expect("fresh E outer after management key rotation");
    let fresh_cleanup = decode_cleanup(&fresh_cleanup);
    let fresh_ack = acknowledged_exchange(
        &fresh_cleanup,
        NOW + 906,
        "identity-response-key-rotated",
        13,
        3,
    );
    let mut fresh_request = request.clone();
    fresh_request.cleanup = fresh_cleanup;
    fresh_request.acknowledge_exchange = fresh_ack;
    assert_eq!(
        crowsi_credential_authority_contracts::endpoint_revocation_execution_cancel_cleanup_complete_request_digest(&fresh_request).expect("fresh stable digest"),
        accepted.cleanup_complete_request_sha256,
    );
    let recovered = rotated
        .complete_pending_revocation_cancellation_cleanup(
            &transport(CLEANUP_COMPLETE_ROUTE, &fresh_request),
            NOW + 907,
        )
        .expect("fresh Ack recovers completed delivery after compaction");
    let recovered = crowsi_credential_authority_contracts::decode_endpoint_revocation_execution_cancellation_cleanup_complete_strict(&recovered)
        .expect("recovered cleanup delivery proof");
    assert_eq!(recovered.cleanup_complete_id, accepted.cleanup_complete_id);
    assert_eq!(recovered.token, accepted.token);
    assert_ne!(recovered.signature, accepted.signature);
    crate::gateway_peer_response::apply(
        inactive,
        &test_config_with_identity(10, "identity-response-key-rotated", 13, 3).document,
        &transport(CLEANUP_COMPLETE_ROUTE, &fresh_request),
        &serde_json::to_vec(&recovered).expect("recovered wire"),
        NOW + 907,
    )
    .expect("inactive source accepts typed cleanup delivery recovery");
    let mut substituted = fresh_request;
    substituted.request_id = "internal-cancel-cleanup-complete-substituted".into();
    assert!(
        rotated
            .complete_pending_revocation_cancellation_cleanup(
                &transport(CLEANUP_COMPLETE_ROUTE, &substituted),
                NOW + 908,
            )
            .is_err()
    );
}
const CLEANUP_COMPLETE_ROUTE: &str = "revocation-execution-cancel-cleanup-complete";
