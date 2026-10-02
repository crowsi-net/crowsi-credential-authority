use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use crate::host_config_types::HostProviderRoute;

#[test]
fn provider_state_is_required_and_must_not_alias_host_or_gateway_paths() {
    let mut missing =
        serde_json::to_value(route("/var/lib/crowsi/provider-a")).expect("provider route");
    missing
        .as_object_mut()
        .expect("provider object")
        .remove("state_directory");
    assert!(serde_json::from_value::<HostProviderRoute>(missing).is_err());

    let mut host = crate::gateway_peer_response_config::trust();
    host.provider_operations = vec![route(&host.management_state_directory)];
    assert!(!crate::host_config_roles::paths(&host));

    host.provider_operations = vec![route("/var/lib/crowsi/replay")];
    let (gateway, _) = crate::gateway_config_validation_tests::documents();
    assert!(!crate::gateway_validation::deployment_paths_distinct(
        &host, &gateway
    ));
}

#[test]
fn provider_state_rejects_writable_parent_leaf_and_symlink() {
    let root = unique("provider-state-validation");
    directory(&root, 0o700);
    let state = root.join("state");
    directory(&state, 0o700);
    assert!(crate::host_files::provider_state_directory(&state).is_ok());

    permissions(&state, 0o770);
    assert!(crate::host_files::provider_state_directory(&state).is_err());
    permissions(&state, 0o700);
    permissions(&root, 0o770);
    assert!(crate::host_files::provider_state_directory(&state).is_err());
    permissions(&root, 0o700);

    fs::remove_dir(&state).expect("remove state");
    let target = root.join("target");
    directory(&target, 0o700);
    symlink(&target, &state).expect("state symlink");
    assert!(crate::host_files::provider_state_directory(&state).is_err());
    fs::remove_dir_all(root).expect("cleanup");
}

fn route(state: &str) -> HostProviderRoute {
    HostProviderRoute {
        service_id: "service-a".into(),
        executable: "/usr/libexec/provider-a".into(),
        executable_sha256: format!("sha256:{}", "11".repeat(32)),
        config_path: "/etc/crowsi/provider-a.json".into(),
        config_sha256: format!("sha256:{}", "22".repeat(32)),
        state_directory: state.into(),
        response_key_id: "provider-response-a".into(),
        response_public_key_hex: "33".repeat(32),
    }
}

fn unique(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::current_dir()
        .expect("current directory")
        .join("target")
        .join(format!("crowsi-{name}-{}-{nonce}", std::process::id()))
}

fn directory(path: &Path, mode: u32) {
    fs::create_dir(path).expect("directory");
    permissions(path, mode);
}

fn permissions(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("permissions");
}
