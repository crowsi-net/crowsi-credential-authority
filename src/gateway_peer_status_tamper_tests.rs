use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{gateway_contract::GatewayPeerDocument, gateway_peer_status::GatewayPeerStatus};

static NEXT: AtomicU64 = AtomicU64::new(10_000);

// CR-11: peer deny ledger and its independent anchor fail closed on rollback or tamper.
#[test]
fn unknown_state_or_anchor_entry_is_rejected() {
    let (root, state, anchor) = directories();
    let peers = peers();
    initialize(&state, &anchor, &peers);
    owner_file(&state.join("unexpected"), b"{}\n");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_file(state.join("unexpected")).expect("remove unknown");
    owner_file(&anchor.join("unexpected"), b"{}\n");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn missing_side_and_stale_generation_are_rejected() {
    let (root, state, anchor) = directories();
    let peers = peers();
    initialize(&state, &anchor, &peers);
    let status = open(&state, &anchor, &peers).expect("initial");
    status.deny("device-a", 2, 100).expect("second revision");
    let anchors = entries(&anchor);
    let latest: serde_json::Value = serde_json::from_slice(
        &fs::read(anchors.last().expect("latest anchor")).expect("anchor wire"),
    )
    .expect("anchor");
    let digest = latest["ledger_sha256"].as_str().expect("digest");
    let latest_generation = state.join(format!("gateway-peer-deny-{}.json", &digest[7..]));
    let stale_generation = entries(&state)
        .into_iter()
        .find(|item| item != &latest_generation && item.extension().is_some_and(|v| v == "json"))
        .expect("stale generation");
    fs::write(
        &latest_generation,
        fs::read(stale_generation).expect("stale wire"),
    )
    .expect("substitute stale");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_dir_all(root).expect("cleanup");

    let (root, state, anchor) = directories();
    initialize(&state, &anchor, &peers);
    fs::remove_file(entries(&anchor).pop().expect("anchor")).expect("remove anchor");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_dir_all(root).expect("cleanup");

    let (root, state, anchor) = directories();
    initialize(&state, &anchor, &peers);
    let generation = entries(&state)
        .into_iter()
        .find(|item| item.extension().is_some_and(|v| v == "json"))
        .expect("generation");
    fs::remove_file(generation).expect("remove generation");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn generation_and_lock_link_or_mode_substitution_is_rejected() {
    let (root, state, anchor) = directories();
    let peers = peers();
    initialize(&state, &anchor, &peers);
    let generation = entries(&state)
        .into_iter()
        .find(|item| item.extension().is_some_and(|v| v == "json"))
        .expect("generation");
    fs::set_permissions(&generation, fs::Permissions::from_mode(0o644)).expect("mode");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_dir_all(root).expect("cleanup");

    let (root, state, anchor) = directories();
    initialize(&state, &anchor, &peers);
    fs::hard_link(
        state.join("gateway-peer-status.lock"),
        root.join("lock-alias"),
    )
    .expect("hardlink");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_dir_all(root).expect("cleanup");

    let (root, state, anchor) = directories();
    initialize(&state, &anchor, &peers);
    fs::remove_file(state.join("gateway-peer-status.lock")).expect("remove lock");
    symlink(root.join("missing"), state.join("gateway-peer-status.lock")).expect("symlink");
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

include!("gateway_peer_status_tamper_support.rs");
