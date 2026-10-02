use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    gateway_peer_response_fixture::{DEVICE_A, DEVICE_C, NOW, exchange, peers},
    gateway_peer_status::GatewayPeerStatus,
};

static NEXT: AtomicU64 = AtomicU64::new(30_000);

// ID-53: completed is withheld until the independent peer deny ledger commits.
#[test]
fn failed_peer_deny_is_reconciled_idempotently_and_restart_durable() {
    let root = std::env::temp_dir().join(format!(
        "crowsi-peer-response-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let state = root.join("state");
    let anchor = root.join("anchor");
    for path in [&root, &state, &anchor] {
        fs::create_dir(path).expect("directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    let peers = peers();
    super::gateway_peer_status_tests::initialize(&state, &anchor, &peers);
    let status =
        GatewayPeerStatus::open(&state, &anchor, "deployment-1", 1, &peers).expect("status");
    let (request, response) = exchange();
    let trust = crate::gateway_peer_response_config::trust();
    fs::write(state.join("uncommitted-crash"), b"{}\n").expect("failpoint");
    assert!(
        crate::gateway_peer_response::apply(&status, &trust, &request, &response, NOW).is_err()
    );
    fs::remove_file(state.join("uncommitted-crash")).expect("repair");
    assert!(
        status
            .allows(DEVICE_A, &format!("sha256:{}", "a".repeat(64)), "request-a")
            .expect("still allowed before reconcile")
    );
    crate::gateway_peer_response::apply(&status, &trust, &request, &response, NOW)
        .expect("reconcile deny");
    crate::gateway_peer_response::apply(&status, &trust, &request, &response, NOW)
        .expect("idempotent replay");
    let reopened =
        GatewayPeerStatus::open(&state, &anchor, "deployment-1", 1, &peers).expect("restart");
    assert!(
        !reopened
            .allows(DEVICE_A, &format!("sha256:{}", "a".repeat(64)), "request-a")
            .expect("A remains denied")
    );
    assert!(
        reopened
            .allows(DEVICE_C, &format!("sha256:{}", "c".repeat(64)), "request-c")
            .expect("C remains active")
    );
    fs::remove_dir_all(root).expect("cleanup");
}
