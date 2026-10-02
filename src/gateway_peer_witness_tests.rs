use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use crate::{
    gateway_peer_head_types::{PeerStatusHeadEntryV1, PeerStatusHeadV1, RESPONSE_SCHEMA},
    gateway_peer_status::GatewayPeerStatus,
};

#[test]
fn signed_authority_head_repairs_coordinated_local_tail_rollback() {
    let (root, state, anchor) = super::gateway_peer_status_tests::directories();
    let peers = vec![
        super::gateway_peer_status_tests::peer("device-a", 'a'),
        super::gateway_peer_status_tests::peer("device-b", 'b'),
    ];
    super::gateway_peer_status_tests::initialize(&state, &anchor, &peers);
    let backup_state = root.join("backup-state");
    let backup_anchor = root.join("backup-anchor");
    copy_directory(&state, &backup_state);
    copy_directory(&anchor, &backup_anchor);
    let status = open(&state, &anchor, &peers).expect("open");
    let head = head();
    status.reconcile_head(&head).expect("current witness");
    assert!(
        !status
            .allows("device-a", &digest('a'), "request-a")
            .expect("denied")
    );
    drop(status);
    restore(&backup_state, &state);
    restore(&backup_anchor, &anchor);
    let rolled_back = open(&state, &anchor, &peers).expect("coherent local rollback");
    assert!(
        rolled_back
            .allows("device-a", &digest('a'), "request-a")
            .expect("old local")
    );
    rolled_back.reconcile_head(&head).expect("forward repair");
    assert!(
        !rolled_back
            .allows("device-a", &digest('a'), "request-a")
            .expect("repaired")
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn missing_initialization_and_old_anchor_tamper_fail_closed() {
    let (root, state, anchor) = super::gateway_peer_status_tests::directories();
    let peers = vec![super::gateway_peer_status_tests::peer("device-a", 'a')];
    assert!(open(&state, &anchor, &peers).is_err());
    super::gateway_peer_status_tests::initialize(&state, &anchor, &peers);
    let status = open(&state, &anchor, &peers).expect("open");
    status.reconcile_head(&head()).expect("second anchor");
    drop(status);
    let old = fs::read_dir(&anchor)
        .expect("anchors")
        .map(|item| item.expect("entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("gateway-peer-anchor-0"))
        })
        .min()
        .expect("old anchor");
    fs::write(&old, b"{}\n").expect("tamper old anchor");
    fs::set_permissions(&old, fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(open(&state, &anchor, &peers).is_err());
    fs::remove_dir_all(root).expect("cleanup");
}

fn head() -> PeerStatusHeadV1 {
    PeerStatusHeadV1 {
        schema: RESPONSE_SCHEMA.into(),
        request_id: "peerhead".into(),
        request_digest_sha256: digest('1'),
        deployment_id: "deployment-1".into(),
        gateway_config_sha256: digest('2'),
        authority_epoch: 1,
        authority_revision: 9,
        entries: vec![entry("device-a", 'a', true), entry("device-b", 'b', false)],
        head_digest_sha256: digest('9'),
        issued_at_epoch_s: 100,
        expires_at_epoch_s: 110,
        key_id: "host-response".into(),
        signature: "0".repeat(128),
    }
}

fn entry(device: &str, value: char, revoked: bool) -> PeerStatusHeadEntryV1 {
    PeerStatusHeadEntryV1 {
        device_id: device.into(),
        certificate_sha256: digest(value),
        request_key_id: format!("request-{value}"),
        registered: true,
        revoked,
        device_revocation_epoch: 2,
    }
}

fn open(
    state: &Path,
    anchor: &Path,
    peers: &[crate::gateway_contract::GatewayPeerDocument],
) -> Result<GatewayPeerStatus, crate::HostError> {
    GatewayPeerStatus::open(state, anchor, "deployment-1", 1, peers)
}

fn restore(source: &Path, target: &Path) {
    fs::remove_dir_all(target).expect("remove current");
    copy_directory(source, target);
}

fn copy_directory(source: &Path, target: &Path) {
    fs::create_dir(target).expect("copy directory");
    fs::set_permissions(target, fs::Permissions::from_mode(0o700)).expect("copy mode");
    for entry in fs::read_dir(source).expect("source") {
        let entry = entry.expect("entry");
        fs::copy(entry.path(), target.join(entry.file_name())).expect("copy file");
    }
}

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}
