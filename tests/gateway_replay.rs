use crowsi_authority_transport::{ReplayGuard, TransportError};
use crowsi_credential_authority::test_support::GatewayReplayGuard;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);

#[test]
fn durable_replay_guard_rejects_nonce_after_restart_and_is_device_scoped() {
    let root = std::env::temp_dir().join(format!(
        "crowsi-gateway-replay-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let anchor = root.with_extension("anchor");
    fs::create_dir(&root).expect("root");
    fs::create_dir(&anchor).expect("anchor");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("mode");
    fs::set_permissions(&anchor, fs::Permissions::from_mode(0o700)).expect("anchor mode");
    GatewayReplayGuard::initialize(&root, &anchor, "deployment-1", 1).expect("initialize");
    GatewayReplayGuard::open(&root, &anchor, "deployment-1", 1)
        .expect("open")
        .consume(
            "device-a",
            &"a".repeat(64),
            &format!("sha256:{}", "1".repeat(64)),
        )
        .expect("first use");
    let reopened = GatewayReplayGuard::open(&root, &anchor, "deployment-1", 1).expect("reopen");
    assert_eq!(
        reopened.consume(
            "device-a",
            &"a".repeat(64),
            &format!("sha256:{}", "1".repeat(64))
        ),
        Err(TransportError::Replay)
    );
    reopened
        .consume(
            "device-b",
            &"a".repeat(64),
            &format!("sha256:{}", "2".repeat(64)),
        )
        .expect("other device");
    fs::remove_dir_all(root).expect("cleanup");
    fs::remove_dir_all(anchor).expect("anchor cleanup");
}
