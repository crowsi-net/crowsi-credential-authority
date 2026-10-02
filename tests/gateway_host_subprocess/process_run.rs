use std::{
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;

use crate::{config::Documents, fixture::Fixture};

pub(crate) fn initialize(fixture: &Fixture, documents: &Documents) {
    let output = Command::new(fixture.path("crowsi-credential-authority-host"))
        .args([
            "initialize-once",
            "--config",
            documents.host.to_str().expect("host path"),
            "--config-sha256",
            &documents.host_digest,
        ])
        .env_clear()
        .output()
        .expect("initialize host");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

pub(crate) fn run(fixture: &Fixture, documents: &Documents, command: &str, wire: &[u8]) -> Vec<u8> {
    let mut child = Command::new(fixture.path("crowsi-credential-authority-host"))
        .args([
            "handle-once",
            "--config",
            documents.host.to_str().expect("host path"),
            "--config-sha256",
            &documents.host_digest,
            "--gateway-config",
            documents.gateway.to_str().expect("gateway path"),
            "--gateway-config-sha256",
            &documents.gateway_digest,
            "--command",
            command,
        ])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn real host");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(wire)
        .expect("request");
    if child
        .wait_timeout(Duration::from_secs(5))
        .expect("bounded wait")
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        panic!("finite authority host timed out");
    }
    let output = child.wait_with_output().expect("host output");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    output.stdout
}
