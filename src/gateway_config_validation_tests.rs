use crate::{
    gateway_config_validation::validate,
    gateway_contract::{GatewayConfigDocument, GatewayPeerDocument},
    host_config_types::HostRootTrust,
};

pub(crate) fn documents() -> (GatewayConfigDocument, HostRootTrust) {
    let root = HostRootTrust {
        schema: "crowsi://credential-authority/host-root-trust/v1".into(),
        configuration_key_id: "configuration-key".into(),
        configuration_public_key_hex: "11".repeat(32),
    };
    let config = GatewayConfigDocument {
        schema: "crowsi://credential-authority/gateway-config/v2".into(),
        deployment_role: "single-central-authority-host".into(),
        deployment_id: "central-authority-1".into(),
        host_executable: "/usr/libexec/crowsi-credential-authority-host".into(),
        host_executable_sha256: format!("sha256:{}", "5".repeat(64)),
        host_config_path: "/etc/crowsi/host.json".into(),
        host_config_sha256: format!("sha256:{}", "6".repeat(64)),
        host_process_timeout_ms: 3_000,
        listen_address: "127.0.0.1:7443".into(),
        audience: "crowsi-authority".into(),
        replay_state_directory: "/var/lib/crowsi/replay".into(),
        replay_anchor_directory: "/var/lib/crowsi/replay-anchor".into(),
        peer_status_state_directory: "/var/lib/crowsi/peer-status".into(),
        peer_status_anchor_directory: "/var/lib/crowsi/peer-status-anchor".into(),
        server_certificate_der_hex: "00".into(),
        server_private_key_path: "/etc/crowsi/server.key".into(),
        client_trust_anchor_der_hex: "00".into(),
        response_signing_key_path: "/etc/crowsi/gateway-response.json".into(),
        response_key_id: "gateway-response-key".into(),
        response_public_key_hex: "22".repeat(32),
        peers: vec![GatewayPeerDocument {
            device_id: "device-a".into(),
            certificate_der_hex: "00".into(),
            certificate_sha256: format!("sha256:{}", "3".repeat(64)),
            request_key_id: "device-a-request-key".into(),
            request_public_key_hex: "44".repeat(32),
        }],
        authority_epoch: 1,
        maximum_connections: 8,
        timeout_ms: 1_000,
        issued_at_epoch_s: 99,
        expires_at_epoch_s: 200,
        configuration_key_id: root.configuration_key_id.clone(),
        signature: "00".repeat(64),
    };
    (config, root)
}

#[test]
fn gateway_response_role_rejects_root_key_id_reuse() {
    let (mut config, root) = documents();
    config.response_key_id = root.configuration_key_id.clone();
    assert!(validate(&config, &root, 100).is_err());
}

#[test]
fn gateway_response_role_rejects_root_public_key_reuse_under_an_alias() {
    let (mut config, root) = documents();
    config.response_public_key_hex = root.configuration_public_key_hex.clone();
    assert!(validate(&config, &root, 100).is_err());
}

#[test]
fn legacy_gateway_config_v1_is_rejected() {
    let (mut config, root) = documents();
    config.schema = "crowsi://credential-authority/gateway-config/v1".into();
    assert!(validate(&config, &root, 100).is_err());
}

#[test]
fn gateway_v2_missing_finite_host_field_or_unknown_alias_is_closed() {
    let (config, _) = documents();
    let mut missing = serde_json::to_value(&config).expect("value");
    missing
        .as_object_mut()
        .expect("object")
        .remove("host_config_sha256");
    assert!(serde_json::from_value::<GatewayConfigDocument>(missing).is_err());
    let mut unknown = serde_json::to_value(config).expect("value");
    unknown["authority_executable"] = serde_json::Value::String("/tmp/legacy".into());
    assert!(serde_json::from_value::<GatewayConfigDocument>(unknown).is_err());
}
