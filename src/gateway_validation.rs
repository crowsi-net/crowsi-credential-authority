use std::collections::BTreeSet;

use crate::{gateway_contract::GatewayConfigDocument, host_config_types::HostConfigDocument};

pub(crate) fn compatible(host: &HostConfigDocument, gateway: &GatewayConfigDocument) -> bool {
    host.deployment_role == "single-central-authority-host"
        && host.authority_epoch == gateway.authority_epoch
        && key_roles_distinct(host, gateway)
        && deployment_paths_distinct(host, gateway)
        && device_coverage_exact(host, gateway)
}

fn device_coverage_exact(host: &HostConfigDocument, gateway: &GatewayConfigDocument) -> bool {
    let managed = host
        .device_proof_keys
        .iter()
        .map(|item| item.device_id.as_str())
        .collect::<BTreeSet<_>>();
    let peers = gateway
        .peers
        .iter()
        .map(|item| item.device_id.as_str())
        .collect::<BTreeSet<_>>();
    !managed.is_empty()
        && host.device_proof_keys.len() == gateway.peers.len()
        && managed.len() == host.device_proof_keys.len()
        && managed == peers
}

pub(crate) fn deployment_paths_distinct(
    host: &HostConfigDocument,
    gateway: &GatewayConfigDocument,
) -> bool {
    let authority = vec![
        &host.authority_store_directory,
        &host.authority_anchor_directory,
        &host.operation_state_directory,
        &host.management_state_directory,
        &host.management_anchor_directory,
        &host.response_signing_key_path,
        &host.management_projection_signing_key_path,
        &host.revocation_execution_reservation_signing_key_path,
    ];
    let authority = authority
        .into_iter()
        .chain(host.provider_operations.iter().flat_map(|route| {
            [
                &route.executable,
                &route.config_path,
                &route.state_directory,
            ]
        }))
        .collect::<Vec<_>>();
    let edge = [
        &gateway.host_executable,
        &gateway.host_config_path,
        &gateway.replay_state_directory,
        &gateway.replay_anchor_directory,
        &gateway.peer_status_state_directory,
        &gateway.peer_status_anchor_directory,
        &gateway.server_private_key_path,
        &gateway.response_signing_key_path,
    ];
    authority
        .iter()
        .all(|left| edge.iter().all(|right| left != right))
}

fn key_roles_distinct(host: &HostConfigDocument, gateway: &GatewayConfigDocument) -> bool {
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let host_roles = [
        (&host.identity_key_id, &host.identity_public_key_hex),
        (
            &host.management_projection_key_id,
            &host.management_projection_public_key_hex,
        ),
        (
            &host.revocation_execution_reservation_key_id,
            &host.revocation_execution_reservation_public_key_hex,
        ),
        (
            &host.current_status_key_id,
            &host.current_status_public_key_hex,
        ),
        (
            &host.user_verification_key_id,
            &host.user_verification_public_key_hex,
        ),
        (
            &host.identity_response_key_id,
            &host.identity_response_public_key_hex,
        ),
        (&host.response_key_id, &host.response_public_key_hex),
    ];
    host_roles
        .into_iter()
        .all(|(id, key)| ids.insert(id) && keys.insert(key))
        && host.provider_operations.iter().all(|item| {
            ids.insert(&item.response_key_id) && keys.insert(&item.response_public_key_hex)
        })
        && host
            .device_proof_keys
            .iter()
            .all(|item| ids.insert(&item.device_proof_key_ref) && keys.insert(&item.public_key_hex))
        && ids.insert(&gateway.response_key_id)
        && keys.insert(&gateway.response_public_key_hex)
        && gateway.peers.iter().all(|peer| {
            ids.insert(&peer.request_key_id) && keys.insert(&peer.request_public_key_hex)
        })
}
