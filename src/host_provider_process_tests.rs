use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use crate::{host_config_types::HostProviderRoute, host_provider_process};

static PROCESS_TESTS: Mutex<()> = Mutex::new(());

#[test]
fn provider_empty_stderr_is_valid_and_output_is_bounded() {
    let fixture = Fixture::new("printf '{\"ok\":true}'");
    let output =
        host_provider_process::exchange(&fixture.route, "reissue", b"{}").expect("finite provider");
    assert_eq!(output, br#"{"ok":true}"#);
}

#[test]
fn provider_parent_success_kills_grandchild_without_pipe_hang() {
    let fixture = Fixture::new("sleep 30 & echo $! > \"$CROWSI_PIDFILE\"; printf '{}'");
    let started = Instant::now();
    assert_eq!(
        host_provider_process::exchange(&fixture.route, "reissue", b"{}").expect("response"),
        b"{}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let pid = fs::read_to_string(&fixture.pidfile).expect("grandchild pid");
    assert!(gone(pid.trim()));
}

#[test]
fn provider_timeout_kills_its_process_group() {
    let fixture = Fixture::new("sleep 30 & echo $! > \"$CROWSI_PIDFILE\"; wait");
    let started = Instant::now();
    assert!(host_provider_process::exchange(&fixture.route, "reissue", b"{}").is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
    let pid = fs::read_to_string(&fixture.pidfile).expect("grandchild pid");
    assert!(gone(pid.trim()));
}

#[test]
fn provider_that_never_reads_large_stdin_is_bounded_and_killed() {
    let fixture = Fixture::new("echo $$ > \"$CROWSI_PIDFILE\"; sleep 30");
    let started = Instant::now();
    assert!(
        host_provider_process::exchange(&fixture.route, "reissue", &vec![b'x'; 2_097_152]).is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let pid = fs::read_to_string(&fixture.pidfile).expect("provider pid");
    assert!(gone(pid.trim()));
}

struct Fixture {
    _serial: MutexGuard<'static, ()>,
    root: PathBuf,
    pidfile: PathBuf,
    route: HostProviderRoute,
}

impl Fixture {
    fn new(body: &str) -> Self {
        let serial = PROCESS_TESTS.lock().expect("provider process test lock");
        let root = unique();
        fs::create_dir(&root).expect("fixture directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("directory mode");
        let pidfile = root.join("child.pid");
        let script = root.join("provider");
        let config = root.join("provider.json");
        let state = root.join("provider-state");
        fs::create_dir(&state).expect("state directory");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("state mode");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nexport CROWSI_PIDFILE='{}'\n{body}\n",
                pidfile.display()
            ),
        )
        .expect("script");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("script mode");
        fs::write(&config, b"{}").expect("config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).expect("config mode");
        let route = HostProviderRoute {
            service_id: "service-a".into(),
            executable: text(&script),
            executable_sha256: digest(&script),
            config_path: text(&config),
            config_sha256: digest(&config),
            state_directory: text(&state),
            response_key_id: "provider-response".into(),
            response_public_key_hex: "11".repeat(32),
        };
        Self {
            _serial: serial,
            root,
            pidfile,
            route,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn unique() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::current_dir()
        .expect("current directory")
        .join("target")
        .join(format!(
            "crowsi-provider-process-{}-{nonce}",
            std::process::id()
        ))
}

fn digest(path: &Path) -> String {
    crate::host_crypto::digest(&fs::read(path).expect("fixture bytes"))
}

fn text(path: &Path) -> String {
    path.to_str().expect("utf8 path").to_owned()
}

fn gone(pid: &str) -> bool {
    let process = PathBuf::from(format!("/proc/{pid}"));
    for _ in 0..50 {
        if !process.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}
