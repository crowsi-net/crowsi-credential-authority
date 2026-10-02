#[test]
fn exact_cancel_is_byte_stable_then_resigned_after_management_key_rotation() {
    let accepted = accepted_cancel();
    let stable = handler(
        &accepted.fixture,
        7,
        "projection-key",
        "management-audience",
    );
    assert_eq!(
        stable
            .recover_cancel_response(&accepted.envelope, "device-a", NOW + 1)
            .expect("stable response")
            .expect("accepted"),
        accepted.original_wire
    );

    let context_changed = handler(
        &accepted.fixture,
        7,
        "projection-key",
        "management-audience-v2",
    );
    let changed_wire = context_changed
        .recover_cancel_response(&accepted.envelope, "device-a", NOW + 2)
        .expect("context recovery")
        .expect("accepted");
    assert_ne!(changed_wire, accepted.original_wire);
    let changed =
        crowsi_credential_authority_contracts::decode_management_projection_strict(&changed_wire)
            .expect("context projection");
    assert_eq!(changed.audience, "management-audience-v2");

    let disjoint =
        crate::management_v2_journal_fixture::record("owner", "device-c", "after-cancel");
    accepted
        .fixture
        .journal()
        .insert(disjoint, NOW + 2)
        .expect("advance owner projection revision");
    let rotated = handler(
        &accepted.fixture,
        8,
        "projection-key-rotated",
        "management-audience",
    );
    let wire = rotated
        .recover_cancel_response(&accepted.envelope, "device-a", NOW + 301)
        .expect("historic response")
        .expect("accepted");
    let projection =
        crowsi_credential_authority_contracts::decode_management_projection_strict(&wire)
            .expect("projection");
    assert_eq!(projection.key_id, "projection-key-rotated");
    assert_eq!(projection.snapshot_revision, 4);
    let envelope_wire = serde_json::to_vec(&accepted.envelope).expect("envelope wire");
    crowsi_credential_authority_contracts::decode_endpoint_management_envelope_strict(
        &envelope_wire,
    )
    .expect("valid historic envelope shape");
    crowsi_credential_authority_contracts::verify_endpoint_historic_cancel_projection_at(
        &projection,
        &accepted.envelope,
        "device-a",
        &crowsi_credential_authority_contracts::EndpointHistoricCancelProjectionTrustV1 {
            issuer: "projection-issuer",
            audience: "management-audience",
            key_id: "projection-key-rotated",
            public_key_hex: &crate::gateway_peer_response_identity::public(8),
            minimum_snapshot_revision: 4,
            now_epoch_s: NOW + 301,
        },
    )
    .expect("current-key historic projection");
}

fn handler(
    fixture: &Fixture,
    key: u8,
    key_id: &str,
    audience: &str,
) -> crate::management_v2_handler::ManagementV2Handler {
    let mut document = crate::gateway_peer_response_config::trust();
    document.management_projection_key_id = key_id.into();
    document.management_audience = audience.into();
    document.management_projection_public_key_hex =
        crate::gateway_peer_response_identity::public(key);
    crate::management_v2_handler::ManagementV2Handler {
        core: crate::management_v2_host_context::ManagementHostContext {
            config: crate::host_config::VerifiedHostConfig {
                document,
                response_signing_key: crate::gateway_peer_response_identity::key(6),
                management_projection_signing_key: crate::gateway_peer_response_identity::key(key),
                revocation_execution_reservation_signing_key:
                    crate::gateway_peer_response_identity::key(12),
            },
        },
        journal: fixture.journal(),
    }
}
