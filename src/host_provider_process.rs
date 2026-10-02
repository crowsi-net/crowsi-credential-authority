use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

use crate::{HostError, host_config_types::HostProviderRoute, host_files};

#[cfg(not(test))]
const PROCESS_TIMEOUT: Duration = Duration::from_secs(8);
#[cfg(test)]
const PROCESS_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) fn exchange(
    route: &HostProviderRoute,
    command: &str,
    request: &[u8],
) -> Result<Vec<u8>, HostError> {
    host_files::provider_state_directory(std::path::Path::new(&route.state_directory))?;
    let executable = host_files::pin_executable(
        std::path::Path::new(&route.executable),
        &route.executable_sha256,
    )?;
    let config = host_files::pin_owner_file(
        std::path::Path::new(&route.config_path),
        262_144,
        &route.config_sha256,
    )?;
    let mut child = Command::new(executable.path())
        .args([
            "handle-once",
            "--config",
            config.path(),
            "--command",
            command,
        ])
        .env_clear()
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| HostError::Unavailable)?;
    let started = Instant::now();
    let _pinned = (executable.retain(), config.retain());
    let (Some(input), Some(output), Some(errors)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        terminate_group(&mut child);
        return Err(HostError::Unavailable);
    };
    let writer = write(input, request.to_vec());
    let stdout = reader(output, false);
    let stderr = reader(errors, true);
    let result = (|| {
        receive(&writer, remaining(started)?)??;
        let status = child
            .wait_timeout(remaining(started)?)
            .map_err(|_| HostError::Unavailable)?
            .ok_or(HostError::Unavailable)?;
        kill_group(&child, Signal::SIGKILL);
        let output = receive(&stdout, remaining(started)?)??;
        let errors = receive(&stderr, remaining(started)?)??;
        if !status.success() || !errors.is_empty() {
            return Err(HostError::Unavailable);
        }
        Ok(output)
    })();
    terminate_group(&mut child);
    result
}

fn write<W: Write + Send + 'static>(
    mut output: W,
    wire: Vec<u8>,
) -> Receiver<Result<(), HostError>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = output.write_all(&wire).map_err(|_| HostError::Unavailable);
        drop(output);
        let _ = sender.send(result);
    });
    receiver
}

fn reader<R: Read + Send + 'static>(
    mut input: R,
    allow_empty: bool,
) -> Receiver<Result<Vec<u8>, HostError>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut output = Vec::new();
        let result = input
            .by_ref()
            .take(65_537)
            .read_to_end(&mut output)
            .map_err(|_| HostError::Unavailable)
            .and_then(|_| validate_output(output, allow_empty));
        let _ = sender.send(result);
    });
    receiver
}

fn validate_output(output: Vec<u8>, allow_empty: bool) -> Result<Vec<u8>, HostError> {
    if output.len() > 65_536 || (!allow_empty && output.is_empty()) {
        Err(HostError::Unavailable)
    } else {
        Ok(output)
    }
}

fn receive<T>(value: &Receiver<T>, timeout: Duration) -> Result<T, HostError> {
    value
        .recv_timeout(timeout)
        .map_err(|_| HostError::Unavailable)
}

fn remaining(started: Instant) -> Result<Duration, HostError> {
    PROCESS_TIMEOUT
        .checked_sub(started.elapsed())
        .filter(|value| !value.is_zero())
        .ok_or(HostError::Unavailable)
}

include!("host_provider_process_terminate.rs");
