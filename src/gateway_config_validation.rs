use std::{collections::BTreeSet, path::Path};

use crate::{HostError, gateway_contract::GatewayConfigDocument, host_config_types::HostRootTrust};

pub(crate) fn validate(
    value: &GatewayConfigDocument,
    root: &HostRootTrust,
    now: u64,
) -> Result<(), HostError> {
    let mut devices = BTreeSet::new();
    let mut certificates = BTreeSet::new();
    let mut request_ids = BTreeSet::new();
    let mut request_keys = BTreeSet::new();
    let root_roles_distinct = request_ids.insert(&root.configuration_key_id)
        && request_ids.insert(&value.response_key_id)
        && request_keys.insert(&root.configuration_public_key_hex)
        && request_keys.insert(&value.response_public_key_hex);
    let valid = value.schema == "crowsi://credential-authority/gateway-config/v2"
        && value.deployment_role == "single-central-authority-host"
        && id(&value.deployment_id, 128)
        && root.schema == "crowsi://credential-authority/host-root-trust/v1"
        && value.configuration_key_id == root.configuration_key_id
        && root_roles_distinct
        && value.authority_epoch > 0
        && (2..=64).contains(&value.maximum_connections)
        && (100..=30_000).contains(&value.timeout_ms)
        && (100..=30_000).contains(&value.host_process_timeout_ms)
        && digest(&value.host_executable_sha256)
        && digest(&value.host_config_sha256)
        && value.issued_at_epoch_s <= now
        && now < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= 31_536_000
        && id(&value.listen_address, 256)
        && value.listen_address.contains(':')
        && id(&value.audience, 256)
        && id(&value.response_key_id, 128)
        && key(&value.response_public_key_hex)
        && id(&value.configuration_key_id, 128)
        && paths(value)
        && hex_bytes(&value.server_certificate_der_hex, 262_144)
        && hex_bytes(&value.client_trust_anchor_der_hex, 262_144)
        && !value.peers.is_empty()
        && value.peers.len() <= 10_000
        && value.peers.iter().all(|peer| {
            id(&peer.device_id, 128)
                && digest(&peer.certificate_sha256)
                && id(&peer.request_key_id, 128)
                && key(&peer.request_public_key_hex)
                && hex_bytes(&peer.certificate_der_hex, 262_144)
                && devices.insert(&peer.device_id)
                && certificates.insert(&peer.certificate_sha256)
                && request_ids.insert(&peer.request_key_id)
                && request_keys.insert(&peer.request_public_key_hex)
        });
    if valid {
        Ok(())
    } else {
        Err(HostError::ConfigInvalid)
    }
}

fn paths(value: &GatewayConfigDocument) -> bool {
    let paths = [
        &value.host_executable,
        &value.host_config_path,
        &value.replay_state_directory,
        &value.replay_anchor_directory,
        &value.peer_status_state_directory,
        &value.peer_status_anchor_directory,
        &value.server_private_key_path,
        &value.response_signing_key_path,
    ];
    let distinct = paths.iter().collect::<BTreeSet<_>>().len() == paths.len();
    paths.iter().all(|item| Path::new(item).is_absolute()) && distinct
}
fn id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn key(value: &str) -> bool {
    lower_hex(value, 32)
}
fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|item| lower_hex(item, 32))
}
fn hex_bytes(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max * 2
        && value.len().is_multiple_of(2)
        && lower_hex(value, value.len() / 2)
}
fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn decode(value: &str, max: usize) -> Result<Vec<u8>, HostError> {
    if !hex_bytes(value, max) {
        return Err(HostError::ConfigInvalid);
    }
    hex::decode(value).map_err(|_| HostError::ConfigInvalid)
}
