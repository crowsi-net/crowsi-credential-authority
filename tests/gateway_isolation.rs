use crowsi_authority_transport::{ReplayGuard, TransportError};
use crowsi_credential_authority::test_support::GatewayReplayGuard;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);

// E2E-13: one peer's replay flood cannot consume another peer's durable quota.
#[test]
fn peer_quota_and_expiry_preserve_other_endpoint_availability() {
    let root = std::env::temp_dir().join(format!(
        "crowsi-gateway-isolation-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let anchor = root.with_extension("anchor");
    fs::create_dir(&root).expect("root");
    fs::create_dir(&anchor).expect("anchor");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("mode");
    fs::set_permissions(&anchor, fs::Permissions::from_mode(0o700)).expect("anchor mode");
    GatewayReplayGuard::initialize(&root, &anchor, "deployment-1", 1).expect("initialize");
    let guard = GatewayReplayGuard::open(&root, &anchor, "deployment-1", 1).expect("guard");
    for value in 0..256_u64 {
        guard
            .consume("device-a", &format!("{value:064x}"), &digest(value))
            .unwrap_or_else(|error| panic!("A quota slot {value}: {error}"));
    }
    assert_eq!(
        guard.consume("device-a", &format!("{:064x}", 257), &digest(257)),
        Err(TransportError::Unavailable)
    );
    guard
        .consume("device-b", &"b".repeat(64), &digest(300))
        .expect("B remains available");
    let reopened = GatewayReplayGuard::open(&root, &anchor, "deployment-1", 1).expect("restart");
    assert_eq!(
        reopened.consume("device-b", &"b".repeat(64), &digest(300)),
        Err(TransportError::Replay)
    );
    fs::remove_dir_all(root).expect("cleanup");
    fs::remove_dir_all(anchor).expect("anchor cleanup");
}

fn digest(value: u64) -> String {
    format!("sha256:{value:064x}")
}
