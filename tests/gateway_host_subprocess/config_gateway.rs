use serde_json::json;
use std::path::{Path, PathBuf};

use crate::{
    config_files::Files,
    fixture::{Fixture, digest, key, public, sign},
    identity::{DEVICE_A, DEVICE_B},
};

pub(crate) fn write(
    fixture: &Fixture,
    files: &Files,
    host: &Path,
    host_digest: &str,
) -> (PathBuf, String) {
    let mut value = json!({
        "schema":"crowsi://credential-authority/gateway-config/v2",
        "deployment_role":"single-central-authority-host",
        "deployment_id":"central-authority-1",
        "host_executable":files.executable,
        "host_executable_sha256":files.executable_digest,
        "host_config_path":host,"host_config_sha256":host_digest,
        "host_process_timeout_ms":3000,
        "listen_address":"127.0.0.1:7443","audience":"crowsi-authority-transport",
        "replay_state_directory":fixture.replay,
        "replay_anchor_directory":fixture.replay_anchor,
        "peer_status_state_directory":fixture.peer_state,
        "peer_status_anchor_directory":fixture.peer_anchor,
        "server_certificate_der_hex":"00",
        "server_private_key_path":files.server_private_key,
        "client_trust_anchor_der_hex":"00",
        "response_signing_key_path":files.gateway_response_key,
        "response_key_id":"gateway-response-key","response_public_key_hex":public(11),
        "peers":[peer(DEVICE_A,'a',12),peer(DEVICE_B,'b',13)],
        "authority_epoch":1,"maximum_connections":8,"timeout_ms":3000,
        "issued_at_epoch_s":fixture.now-1,"expires_at_epoch_s":fixture.now+3600,
        "configuration_key_id":"root-config-key","signature":""
    });
    let wire = sign("CROWSI-AUTHORITY-GATEWAY-CONFIG-V2", &mut value, &key(1));
    let path = fixture.write("gateway-config.json", &wire);
    (path, digest(&wire))
}

fn peer(device: &str, byte: char, key_byte: u8) -> serde_json::Value {
    json!({"device_id":device,"certificate_der_hex":"00",
        "certificate_sha256":format!("sha256:{}",byte.to_string().repeat(64)),
        "request_key_id":format!("request-{byte}"),
        "request_public_key_hex":public(key_byte)})
}
