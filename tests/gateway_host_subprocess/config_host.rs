use serde_json::json;
use std::path::PathBuf;

use crate::{
    config_files::Files,
    fixture::{Fixture, digest, key, public, sign},
    identity::{
        DEVICE_A, DEVICE_B, ISSUER, MANAGEMENT_AUDIENCE, OWNER, PAIRWISE, REGISTRATION_AUDIENCE,
        SERVICE,
    },
};

pub(crate) fn write(fixture: &Fixture, files: &Files) -> (PathBuf, String) {
    let mut value = json!({
        "schema":"crowsi://credential-authority/host-config/v4",
        "deployment_role":"single-central-authority-host",
        "authority_store_directory":fixture.store,
        "authority_anchor_directory":fixture.authority_anchor,
        "operation_state_directory":fixture.operations,
        "management_state_directory":fixture.management_state,
        "management_anchor_directory":fixture.anchors,
        "response_signing_key_path":files.response_key,
        "response_key_id":"host-response-key","response_public_key_hex":public(6),
        "identity_issuer":ISSUER,"registration_audience":REGISTRATION_AUDIENCE,
        "management_audience":MANAGEMENT_AUDIENCE,
        "management_projection_issuer":"crowsi-credential-authority",
        "management_projection_signing_key_path":files.projection_key,
        "management_projection_key_id":"projection-key",
        "management_projection_public_key_hex":public(7),
        "revocation_execution_reservation_signing_key_path":files.reservation_key,
        "revocation_execution_reservation_key_id":"reservation-key",
        "revocation_execution_reservation_public_key_hex":public(14),
        "revocation_execution_reservation_config_generation":1,
        "identity_key_id":"identity-key","identity_public_key_hex":public(2),
        "current_status_key_id":"status-key","current_status_public_key_hex":public(3),
        "user_verification_key_id":"uv-key","user_verification_public_key_hex":public(4),
        "identity_response_key_id":"identity-response-key",
        "identity_response_public_key_hex":public(5),
        "minimum_identity_config_generation":1,
        "identity_finalization_authority_id":"identity-finalizer",
        "revocation_approval_authority_refs":["recovery-c"],
        "provider_operations":[provider(fixture,files)],
        "owner_mappings":[{"issuer":ISSUER,"service_id":SERVICE,
            "pairwise_subject":PAIRWISE,"opaque_owner_ref":OWNER,
            "account_binding_sha256":"ab".repeat(32)}],
        "device_proof_keys":[device(DEVICE_A,9),device(DEVICE_B,10)],
        "authority_epoch":1,"issued_at_epoch_s":fixture.now-1,
        "expires_at_epoch_s":fixture.now+3600,
        "configuration_key_id":"root-config-key","signature":""
    });
    let wire = sign(
        "CROWSI-CREDENTIAL-AUTHORITY-HOST-CONFIG-V4",
        &mut value,
        &key(1),
    );
    let path = fixture.write("host-config.json", &wire);
    (path, digest(&wire))
}

fn provider(fixture: &Fixture, files: &Files) -> serde_json::Value {
    json!({"service_id":SERVICE,"executable":files.provider_executable,
        "executable_sha256":files.provider_executable_digest,"config_path":files.provider_config,
        "config_sha256":files.provider_config_digest,"state_directory":fixture.provider_state,
        "response_key_id":"provider-key",
        "response_public_key_hex":public(8)})
}

fn device(device: &str, byte: u8) -> serde_json::Value {
    let suffix = device.chars().last().expect("device suffix");
    json!({"opaque_owner_ref":OWNER,"device_id":device,
        "device_proof_key_ref":format!("device-proof-{suffix}"),
        "public_key_hex":public(byte),"custody":"hardware-nonexportable",
        "custody_revision":"revision-1"})
}
