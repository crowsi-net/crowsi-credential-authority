#[test]
fn cancel_future_bytes_accept_exact_boundary_and_reject_one_byte_short() {
    let required = committed_cancel_high_water();

    let exact = crate::management_v2_journal_test_environment::Fixture::new();
    let value = revocation_case();
    persist(&exact, &value.record);
    let response = crate::management_v2_journal_cancel_capacity::with_test_limit(required, || {
        escaped_handler(&exact).handle(
            &transport("cancel", &escaped_cancel_envelope(&value)),
            NOW + 1,
        )
    });
    response.expect("exact serialized plus outstanding byte boundary");
    let exact_ledger =
        crate::management_v2_journal_io::read(&exact.state, &exact.anchor, OWNER).expect("ledger");
    assert_eq!(
        crate::management_v2_journal_cancel_capacity::high_water(&exact_ledger).expect("water"),
        required,
    );

    let short = crate::management_v2_journal_test_environment::Fixture::new();
    let value = revocation_case();
    persist(&short, &value.record);
    let response =
        crate::management_v2_journal_cancel_capacity::with_test_limit(required - 1, || {
            escaped_handler(&short).handle(
                &transport("cancel", &escaped_cancel_envelope(&value)),
                NOW + 1,
            )
        });
    assert!(response.is_err());
    let current = short
        .journal()
        .record(OWNER, &value.record.operation.operation_id)
        .expect("pre-cancel record remains");
    assert_eq!(
        current.operation.state,
        ManagementOperationState::AwaitingRevocationFinal,
    );
    let acceptance = current
        .revocation_finalization
        .expect("pre-final acceptance");
    assert!(!acceptance.cancellation_slot_reserved);
    assert_eq!(acceptance.cancellation_recovery_reservation_bytes, 0);
}

fn committed_cancel_high_water() -> u64 {
    let fixture = crate::management_v2_journal_test_environment::Fixture::new();
    let value = revocation_case();
    persist(&fixture, &value.record);
    escaped_handler(&fixture)
        .handle(
            &transport("cancel", &escaped_cancel_envelope(&value)),
            NOW + 1,
        )
        .expect("baseline Cancel");
    let ledger = crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, OWNER)
        .expect("cancelled ledger");
    let acceptance = ledger.records[0]
        .revocation_finalization
        .as_ref()
        .expect("acceptance");
    assert!(acceptance.cancellation_recovery_reservation_bytes > 0);
    crate::management_v2_journal_cancel_capacity::high_water(&ledger).expect("high water")
}

fn escaped_handler(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
) -> crate::management_v2_handler::ManagementV2Handler {
    let mut config = test_config(7);
    config.document.management_projection_issuer = "\\".repeat(256);
    config.document.management_projection_key_id = escaped_id(0);
    config.document.revocation_execution_reservation_key_id = escaped_id(1);
    config.document.identity_response_key_id = escaped_id(2);
    crate::management_v2_handler::ManagementV2Handler {
        core: crate::management_v2_host_context::ManagementHostContext { config },
        journal: fixture.journal(),
    }
}

fn escaped_cancel_envelope(value: &RevocationCase) -> EndpointManagementEnvelopeV2 {
    let mut envelope = cancel_envelope(value);
    envelope.browser_request.request_id = escaped_id(3);
    let crowsi_credential_authority_contracts::EndpointManagementEvidenceV2::Cancel {
        identity_exchange,
        ..
    } = &mut envelope.evidence
    else {
        unreachable!()
    };
    identity_exchange.response.key_id = escaped_id(2);
    identity_exchange.response.signature = hex::encode(
        crate::gateway_peer_response_identity::key(5)
            .sign(
                &ihat_identity_assertion_contracts::canonical_response(&identity_exchange.response)
                    .expect("identity response canonical"),
            )
            .to_bytes(),
    );
    envelope
}

fn escaped_id(marker: usize) -> String {
    let mut value = vec![b'\\'; 128];
    value[marker] = b'"';
    value.into_iter().map(char::from).collect()
}

include!("management_v2_execution_cancellation_capacity_validation_tests.rs");
