use serde_json::json;

use crate::host_config_types::HostConfigDocument;

pub(super) fn trust() -> HostConfigDocument {
    serde_json::from_value(json!({
        "schema":"crowsi://credential-authority/host-config/v4",
        "deployment_role":"single-central-authority-host",
        "authority_store_directory":"/unused/store",
        "authority_anchor_directory":"/unused/authority-anchors",
        "operation_state_directory":"/unused/operations",
        "management_state_directory":"/unused/management-state",
        "management_anchor_directory":"/unused/anchors",
        "response_signing_key_path":"/unused/response-key",
        "response_key_id":"response-key","response_public_key_hex":public(6),
        "identity_issuer":"ihat-authority","registration_audience":"register-audience",
        "management_audience":"management-audience",
        "management_projection_issuer":"projection-issuer",
        "management_projection_signing_key_path":"/unused/projection-key",
        "management_projection_key_id":"projection-key",
        "management_projection_public_key_hex":public(7),
        "revocation_execution_reservation_signing_key_path":"/unused/reservation-key",
        "revocation_execution_reservation_key_id":"reservation-key",
        "revocation_execution_reservation_public_key_hex":public(12),
        "revocation_execution_reservation_config_generation":1,
        "identity_key_id":"identity-key","identity_public_key_hex":public(2),
        "current_status_key_id":"status-key","current_status_public_key_hex":public(3),
        "user_verification_key_id":"uv-key","user_verification_public_key_hex":public(4),
        "identity_response_key_id":"identity-response-key",
        "identity_response_public_key_hex":public(5),
        "minimum_identity_config_generation":1,
        "identity_finalization_authority_id":"identity-finalizer",
        "revocation_approval_authority_refs":["recovery-c"],
        "provider_operations":[],
        "owner_mappings":[{"issuer":"ihat-authority","service_id":"service-a",
            "pairwise_subject":"psu_pairwise-a","opaque_owner_ref":"psa_owner_0000000000000001",
            "account_binding_sha256":"ab".repeat(32)}],
        "device_proof_keys":[],"authority_epoch":1,
        "issued_at_epoch_s":1,"expires_at_epoch_s":20_000,
        "configuration_key_id":"configuration-key","signature":"00".repeat(64)
    }))
    .expect("host trust")
}

fn public(value: u8) -> String {
    super::gateway_peer_response_identity::public(value)
}
