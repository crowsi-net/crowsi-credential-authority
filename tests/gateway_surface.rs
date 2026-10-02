use std::{fs, path::Path};

#[test]
fn central_gateway_is_mtls_peer_bound_and_durable() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = [
        "src/gateway.rs",
        "src/gateway_backend.rs",
        "src/gateway_host_process.rs",
        "src/gateway_peer_guard.rs",
        "src/gateway_peer_status.rs",
        "src/gateway_validation.rs",
    ]
    .iter()
    .map(|path| fs::read_to_string(root.join(path)).expect("gateway source"))
    .collect::<String>();
    let replay = [
        "src/gateway_replay.rs",
        "src/gateway_replay_io.rs",
        "src/gateway_replay_storage.rs",
    ]
    .iter()
    .map(|path| fs::read_to_string(root.join(path)).expect("replay source"))
    .collect::<String>();
    let atomic =
        fs::read_to_string(root.join("src/management_v2_atomic.rs")).expect("atomic source");
    assert!(source.contains("AuthorityServer"));
    assert!(source.contains("new_with_peer_status"));
    assert!(source.contains("PeerStatusIdentity"));
    assert!(source.contains("peer.device_id"));
    assert!(source.contains("peer.client_certificate_sha256"));
    assert!(source.contains("peer.request_key_id"));
    assert!(source.contains("single-central-authority-host"));
    assert!(replay.contains("FlockArg::LockExclusive"));
    assert!(replay.contains("management_v2_atomic::sync"));
    assert!(atomic.contains("sync_all"));
    assert!(!source.contains("MemoryStore"));
    assert!(!source.contains("AuthorityHostCore"));
    assert!(!source.contains("ManagementV2Handler"));
    assert!(!source.contains("FileAuthorityStore"));
    assert!(source.contains("GatewayHostProcess"));
    let contract = fs::read_to_string(root.join("src/gateway_contract.rs")).expect("contract");
    let secret = contract
        .split_once("struct GatewaySigningKeyDocument")
        .expect("secret")
        .1;
    assert!(!secret.contains("derive(Clone"));
    assert!(!secret.contains("derive(Debug"));
    assert!(secret.contains("Zeroizing<String>"));
}

#[test]
fn gateway_only_reaches_the_authority_through_a_pinned_finite_host() {
    // ID-53: the network gateway cannot open authority state or keys in-process.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let contract = fs::read_to_string(root.join("src/gateway_contract.rs")).expect("contract");
    let process = fs::read_to_string(root.join("src/gateway_host_process.rs")).expect("process");
    let cli = [
        "src/host_cli.rs",
        "src/host_cli_config.rs",
        "src/host_cli_gateway.rs",
    ]
    .iter()
    .map(|path| fs::read_to_string(root.join(path)).expect("host cli"))
    .collect::<String>();
    for field in [
        "host_executable",
        "host_executable_sha256",
        "host_config_sha256",
        "host_process_timeout_ms",
    ] {
        assert!(contract.contains(field), "missing {field}");
    }
    assert!(process.contains("pin_executable"));
    assert!(process.contains("pin_owner_file"));
    assert!(process.contains("env_clear"));
    assert!(process.contains("handle-once"));
    assert!(process.contains("management-v2"));
    assert!(cli.contains("--gateway-config"));
    assert!(cli.contains("validate-once"));
    for legacy in [
        "\"snapshot\"",
        "\"prepare\"",
        "\"finish\"",
        "\"cancel\"",
        "\"reconcile\"",
    ] {
        assert!(
            !cli.contains(legacy),
            "legacy host command remains: {legacy}"
        );
    }
}

#[test]
fn gateway_is_a_separate_central_release_binary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("manifest");
    assert!(manifest.contains("name = \"crowsi-credential-authority-gateway\""));
    assert!(option_env!("CARGO_BIN_EXE_crowsi-credential-authority-gateway").is_some());
}
