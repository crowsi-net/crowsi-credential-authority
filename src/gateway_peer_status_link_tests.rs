use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{gateway_contract::GatewayPeerDocument, gateway_peer_status::GatewayPeerStatus};

static NEXT: AtomicU64 = AtomicU64::new(20_000);

#[test]
fn anchor_and_generation_links_or_modes_fail_closed() {
    let (root, state, anchor) = directories();
    let peers = peers();
    initialize(&state, &anchor, &peers);
    let anchor_file = json_file(&anchor);
    fs::set_permissions(&anchor_file, fs::Permissions::from_mode(0o644)).expect("anchor mode");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_dir_all(root).expect("cleanup");

    let (root, state, anchor) = directories();
    initialize(&state, &anchor, &peers);
    fs::hard_link(json_file(&state), root.join("generation-alias")).expect("hardlink");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_dir_all(root).expect("cleanup");

    let (root, state, anchor) = directories();
    initialize(&state, &anchor, &peers);
    let anchor_file = json_file(&anchor);
    let wire = fs::read(&anchor_file).expect("anchor wire");
    fs::remove_file(&anchor_file).expect("remove anchor");
    let target = root.join("anchor-target");
    fs::write(&target, wire).expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
    symlink(target, anchor_file).expect("anchor symlink");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_dir_all(root).expect("cleanup");
}

fn initialize(state: &Path, anchor: &Path, peers: &[GatewayPeerDocument]) {
    super::gateway_peer_status_tests::initialize(state, anchor, peers);
}

fn open(
    state: &Path,
    anchor: &Path,
    peers: &[GatewayPeerDocument],
) -> Result<GatewayPeerStatus, crate::HostError> {
    GatewayPeerStatus::open(state, anchor, "deployment-1", 1, peers)
}

fn directories() -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "crowsi-peer-links-{}-{}",
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

fn json_file(root: &Path) -> PathBuf {
    fs::read_dir(root)
        .expect("directory")
        .map(|item| item.expect("entry").path())
        .find(|item| item.extension().is_some_and(|value| value == "json"))
        .expect("json file")
}

fn peers() -> Vec<GatewayPeerDocument> {
    vec![GatewayPeerDocument {
        device_id: "device-a".into(),
        certificate_der_hex: "00".into(),
        certificate_sha256: format!("sha256:{}", "a".repeat(64)),
        request_key_id: "request-a".into(),
        request_public_key_hex: "b".repeat(64),
    }]
}
