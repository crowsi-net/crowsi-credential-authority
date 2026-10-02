use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatewayPeerDocument {
    pub device_id: String,
    pub certificate_der_hex: String,
    pub certificate_sha256: String,
    pub request_key_id: String,
    pub request_public_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatewayConfigDocument {
    pub schema: String,
    pub deployment_role: String,
    pub deployment_id: String,
    pub host_executable: String,
    pub host_executable_sha256: String,
    pub host_config_path: String,
    pub host_config_sha256: String,
    pub host_process_timeout_ms: u64,
    pub listen_address: String,
    pub audience: String,
    pub replay_state_directory: String,
    pub replay_anchor_directory: String,
    pub peer_status_state_directory: String,
    pub peer_status_anchor_directory: String,
    pub server_certificate_der_hex: String,
    pub server_private_key_path: String,
    pub client_trust_anchor_der_hex: String,
    pub response_signing_key_path: String,
    pub response_key_id: String,
    pub response_public_key_hex: String,
    pub peers: Vec<GatewayPeerDocument>,
    pub authority_epoch: u64,
    pub maximum_connections: usize,
    pub timeout_ms: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub configuration_key_id: String,
    pub signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatewaySigningKeyDocument {
    pub schema: String,
    pub key_id: String,
    pub private_key_hex: zeroize::Zeroizing<String>,
}
