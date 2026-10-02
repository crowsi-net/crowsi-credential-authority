fn handler(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
    projection_key: u8,
) -> crate::management_v2_handler::ManagementV2Handler {
    crate::management_v2_handler::ManagementV2Handler {
        core: crate::management_v2_host_context::ManagementHostContext {
            config: test_config(projection_key),
        },
        journal: fixture.journal(),
    }
}

fn handler_with_identity(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
    projection_key: u8,
    identity_key_id: &str,
    identity_key: u8,
    minimum_identity_generation: u64,
) -> crate::management_v2_handler::ManagementV2Handler {
    crate::management_v2_handler::ManagementV2Handler {
        core: crate::management_v2_host_context::ManagementHostContext {
            config: test_config_with_identity(
                projection_key,
                identity_key_id,
                identity_key,
                minimum_identity_generation,
            ),
        },
        journal: fixture.journal(),
    }
}

pub(crate) fn test_config(projection_key: u8) -> crate::host_config::VerifiedHostConfig {
    test_config_with_identity(projection_key, "identity-response-key", 5, 1)
}

fn test_config_with_identity(
    projection_key: u8,
    identity_key_id: &str,
    identity_key: u8,
    minimum_identity_generation: u64,
) -> crate::host_config::VerifiedHostConfig {
    let mut document = crate::gateway_peer_response_config::trust();
    document.management_projection_key_id = format!("projection-key-{projection_key}");
    document.management_projection_public_key_hex =
        crate::gateway_peer_response_identity::public(projection_key);
    document.identity_response_key_id = identity_key_id.into();
    document.identity_response_public_key_hex =
        crate::gateway_peer_response_identity::public(identity_key);
    document.minimum_identity_config_generation = minimum_identity_generation;
    let identity = crate::gateway_peer_response_identity::identity();
    document
        .device_proof_keys
        .push(crate::host_config_types::HostDeviceKey {
            opaque_owner_ref: OWNER.into(),
            device_id: DEVICE.into(),
            device_proof_key_ref: identity.assertion.device_proof_key_ref,
            public_key_hex: crate::gateway_peer_response_identity::public(12),
            custody: "native-test".into(),
            custody_revision: "1".into(),
        });
    crate::host_config::VerifiedHostConfig {
        document,
        response_signing_key: crate::gateway_peer_response_identity::key(6),
        management_projection_signing_key: crate::gateway_peer_response_identity::key(
            projection_key,
        ),
        revocation_execution_reservation_signing_key: crate::gateway_peer_response_identity::key(
            12,
        ),
    }
}

fn transport<T: serde::Serialize>(command: &str, value: &T) -> SignedRequest {
    SignedRequest {
        peer: PeerBinding {
            device_id: DEVICE.into(),
            certificate_sha256: format!("sha256:{}", "cc".repeat(32)),
            request_key_id: "request-device-c".into(),
            request_public_key_hex: crate::gateway_peer_response_identity::public(12),
        },
        command: command.into(),
        payload: serde_json::to_vec(value).expect("transport payload"),
    }
}

fn slot(fixture: &crate::management_v2_journal_test_environment::Fixture) -> bool {
    fixture
        .journal()
        .record(OWNER, &revocation_case().record.operation.operation_id)
        .expect("record")
        .revocation_finalization
        .expect("finalization")
        .cancellation_slot_reserved
}

include!("management_v2_execution_cancellation_capacity_support.rs");
fn terminal_receipt_evictable(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
) -> bool {
    let ledger = crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, OWNER)
        .expect("ledger");
    crate::management_v2_journal_receipt::terminal_operations(&ledger)
        .contains(&revocation_case().record.operation.operation_id)
}

fn inactive_gateway(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
) -> crate::gateway_peer_status::GatewayPeerStatus {
    use std::{fs, os::unix::fs::PermissionsExt};

    let root = fixture.state.parent().expect("fixture root");
    let state = root.join("cancel-gateway-state");
    let anchor = root.join("cancel-gateway-anchor");
    for path in [&state, &anchor] {
        fs::create_dir(path).expect("gateway directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("gateway mode");
    }
    let peers = crate::gateway_peer_response_fixture::peers();
    crate::gateway_peer_status_tests::initialize(&state, &anchor, &peers);
    let value = crate::gateway_peer_status::GatewayPeerStatus::open(
        &state,
        &anchor,
        "deployment-1",
        1,
        &peers,
    )
    .expect("gateway status");
    value.deny(DEVICE, 2, NOW + 300).expect("inactive source");
    value
}

include!("management_v2_execution_cancellation_test_compaction.rs");
