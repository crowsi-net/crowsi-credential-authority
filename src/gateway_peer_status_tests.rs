use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{gateway_contract::GatewayPeerDocument, gateway_peer_status::GatewayPeerStatus};

static NEXT: AtomicU64 = AtomicU64::new(1);

#[test]
fn peer_deny_is_hot_exact_and_restart_durable() {
    let (root, state, anchor) = directories();
    let peers = vec![peer("device-a", 'a'), peer("device-b", 'b')];
    initialize(&state, &anchor, &peers);
    let status = GatewayPeerStatus::open(&state, &anchor, "deployment-1", 1, &peers).expect("open");
    assert!(
        status
            .allows("device-a", &digest('a'), "request-a")
            .expect("A")
    );
    status.deny("device-a", 2, 100).expect("deny A");
    assert!(
        !status
            .allows("device-a", &digest('a'), "request-a")
            .expect("denied")
    );
    assert!(
        status
            .allows("device-b", &digest('b'), "request-b")
            .expect("B")
    );
    status.deny("device-a", 2, 101).expect("idempotent");
    let reopened =
        GatewayPeerStatus::open(&state, &anchor, "deployment-1", 1, &peers).expect("reopen");
    assert!(
        !reopened
            .allows("device-a", &digest('a'), "request-a")
            .expect("persisted")
    );
    assert!(
        reopened
            .allows("device-a", &digest('a'), "request-b")
            .is_err()
    );
    fs::remove_dir_all(root).expect("cleanup");
}

pub(super) fn initialize(
    state: &std::path::Path,
    anchor: &std::path::Path,
    peers: &[GatewayPeerDocument],
) {
    GatewayPeerStatus::initialize(state, anchor, "deployment-1", 1, peers).expect("initialize");
    let status = GatewayPeerStatus::open(state, anchor, "deployment-1", 1, peers).expect("open");
    status
        .reconcile_head(&active_head(peers))
        .expect("activate configured peers");
}

#[test]
fn unregistered_peer_is_denied_before_replay_while_registered_peer_remains_active() {
    let (root, state, anchor) = directories();
    let peers = vec![peer("device-a", 'a'), peer("device-b", 'b')];
    GatewayPeerStatus::initialize(&state, &anchor, "deployment-1", 1, &peers).expect("initialize");
    let status = GatewayPeerStatus::open(&state, &anchor, "deployment-1", 1, &peers).expect("open");
    let mut head = active_head(&peers);
    head.entries[0].registered = false;
    head.entries[0].device_revocation_epoch = 0;
    status.reconcile_head(&head).expect("signed head state");
    assert!(
        !status
            .allows("device-a", &digest('a'), "request-a")
            .expect("A")
    );
    assert!(
        status
            .allows("device-b", &digest('b'), "request-b")
            .expect("B")
    );
    let reopened =
        GatewayPeerStatus::open(&state, &anchor, "deployment-1", 1, &peers).expect("restart");
    assert!(
        !reopened
            .allows("device-a", &digest('a'), "request-a")
            .expect("A restart")
    );
    fs::remove_dir_all(root).expect("cleanup");
}

fn active_head(peers: &[GatewayPeerDocument]) -> crate::gateway_peer_head_types::PeerStatusHeadV1 {
    crate::gateway_peer_head_types::PeerStatusHeadV1 {
        schema: crate::gateway_peer_head_types::RESPONSE_SCHEMA.into(),
        request_id: "test-head".into(),
        request_digest_sha256: digest('1'),
        deployment_id: "deployment-1".into(),
        gateway_config_sha256: digest('2'),
        authority_epoch: 1,
        authority_revision: 1,
        entries: peers
            .iter()
            .map(
                |peer| crate::gateway_peer_head_types::PeerStatusHeadEntryV1 {
                    device_id: peer.device_id.clone(),
                    certificate_sha256: peer.certificate_sha256.clone(),
                    request_key_id: peer.request_key_id.clone(),
                    registered: true,
                    revoked: false,
                    device_revocation_epoch: 1,
                },
            )
            .collect(),
        head_digest_sha256: digest('3'),
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 110,
        key_id: "test-head-key".into(),
        signature: "0".repeat(128),
    }
}

pub(super) fn directories() -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "crowsi-peer-status-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let state = root.join("state");
    let anchor = root.join("anchor");
    for path in [&root, &state, &anchor] {
        fs::create_dir(path).expect("directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    (root, state, anchor)
}

pub(super) fn peer(device: &str, byte: char) -> GatewayPeerDocument {
    GatewayPeerDocument {
        device_id: device.into(),
        certificate_der_hex: "00".into(),
        certificate_sha256: digest(byte),
        request_key_id: format!("request-{byte}"),
        request_public_key_hex: byte.to_string().repeat(64),
    }
}

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}
