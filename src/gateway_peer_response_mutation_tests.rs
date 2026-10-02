use crowsi_credential_authority_contracts::{
    ManagementOperationState, ManagementProjectionBodyV2, canonical_management_projection,
    decode_management_projection_strict,
};
use ed25519_dalek::Signer;

use crate::{
    gateway_peer_response_fixture::{DEVICE_C, NOW},
    management_v2_journal_fixture::Fixture,
    management_v2_mutation_recovery_test_support::{OWNER, recovery_fixture},
};

#[test]
fn expired_identity_accepts_only_current_signed_exact_historic_mutation() {
    let state = Fixture::new();
    let value = recovery_fixture();
    state
        .journal()
        .insert_consuming_response(value.record.clone(), &[], value.receipt.clone(), NOW)
        .expect("accepted mutation");
    let handler = handler(&state);
    let wire = handler
        .recover_mutation_response(&value.envelope, DEVICE_C, NOW + 31)
        .expect("historic recovery")
        .expect("response");
    let trust = rotated_trust();
    let exchange = crate::gateway_peer_response::identity_exchange(&value.envelope.evidence);
    let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(exchange)
        .expect("identity");
    assert_ne!(exchange.response.key_id, trust.identity_response_key_id);
    assert_ne!(identity.assertion.key_id, trust.identity_key_id);
    assert_ne!(identity.current_status.key_id, trust.current_status_key_id);
    let projection =
        crate::gateway_peer_response_mutation::verify(&trust, &value.request, &wire, NOW + 31)
            .expect("historic gateway verification")
            .expect("historic path");
    assert_eq!(projection.snapshot_revision, 2);

    let mut owner_drift = trust.clone();
    owner_drift.owner_mappings[0].opaque_owner_ref = "psa_owner_drift".into();
    assert!(
        crate::gateway_peer_response_mutation::verify(
            &owner_drift,
            &value.request,
            &wire,
            NOW + 31
        )
        .is_err()
    );

    let mut wrong_peer = copy_request(&value.request);
    wrong_peer.peer.device_id = "device-substituted".into();
    assert!(
        crate::gateway_peer_response_mutation::verify(&trust, &wrong_peer, &wire, NOW + 31)
            .is_err()
    );
    let mut wrong_route = copy_request(&value.request);
    wrong_route.command = "target-options".into();
    assert!(
        crate::gateway_peer_response_mutation::verify(&trust, &wrong_route, &wire, NOW + 31)
            .is_err()
    );

    let mut substituted = decode_management_projection_strict(&wire).expect("projection");
    let ManagementProjectionBodyV2::Operation { operation } = &mut substituted.body else {
        unreachable!()
    };
    operation.state = ManagementOperationState::AwaitingTarget;
    substituted.signature = hex::encode(
        crate::gateway_peer_response_identity::key(8)
            .sign(&canonical_management_projection(&substituted).expect("canonical"))
            .to_bytes(),
    );
    let substituted = serde_json::to_vec(&substituted).expect("wire");
    assert!(
        crate::gateway_peer_response_mutation::verify(
            &trust,
            &value.request,
            &substituted,
            NOW + 31
        )
        .is_err()
    );
}

fn copy_request(
    value: &crowsi_authority_transport::SignedRequest,
) -> crowsi_authority_transport::SignedRequest {
    crowsi_authority_transport::SignedRequest {
        peer: value.peer.clone(),
        command: value.command.clone(),
        payload: value.payload.clone(),
    }
}

fn handler(fixture: &Fixture) -> crate::management_v2_handler::ManagementV2Handler {
    let document = rotated_trust();
    crate::management_v2_handler::ManagementV2Handler {
        core: crate::management_v2_host_context::ManagementHostContext {
            config: crate::host_config::VerifiedHostConfig {
                document,
                response_signing_key: crate::gateway_peer_response_identity::key(6),
                management_projection_signing_key: crate::gateway_peer_response_identity::key(8),
                revocation_execution_reservation_signing_key:
                    crate::gateway_peer_response_identity::key(12),
            },
        },
        journal: fixture.journal(),
    }
}

fn rotated_trust() -> crate::host_config_types::HostConfigDocument {
    let mut value = crate::gateway_peer_response_config::trust();
    value.management_projection_key_id = "projection-key-rotated".into();
    value.management_projection_public_key_hex = crate::gateway_peer_response_identity::public(8);
    value.identity_response_key_id = "identity-response-key-rotated".into();
    value.identity_response_public_key_hex = crate::gateway_peer_response_identity::public(9);
    value.identity_key_id = "identity-key-rotated".into();
    value.identity_public_key_hex = crate::gateway_peer_response_identity::public(10);
    value.current_status_key_id = "status-key-rotated".into();
    value.current_status_public_key_hex = crate::gateway_peer_response_identity::public(11);
    assert_eq!(value.owner_mappings[0].opaque_owner_ref, OWNER);
    value
}
