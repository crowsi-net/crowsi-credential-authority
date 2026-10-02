use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    process::{Child, Command},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

use crate::HostError;

pub(super) fn run(
    mut command: Command,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, HostError> {
    let mut child = command
        .process_group(0)
        .spawn()
        .map_err(|_| HostError::Unavailable)?;
    let started = Instant::now();
    let (Some(input), Some(output), Some(errors)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        terminate(&mut child);
        return Err(HostError::Unavailable);
    };
    let writer = write(input, request.to_vec());
    let stdout = reader(output, 1_048_576, false);
    let stderr = reader(errors, 65_536, true);
    let result = (|| {
        receive(&writer, remaining(started, timeout)?)?.map_err(|()| HostError::Unavailable)?;
        let status = child
            .wait_timeout(remaining(started, timeout)?)
            .map_err(|_| HostError::Unavailable)?
            .ok_or(HostError::Unavailable)?;
        kill_group(&child, Signal::SIGKILL);
        let output = receive(&stdout, remaining(started, timeout)?)??;
        let errors = receive(&stderr, remaining(started, timeout)?)??;
        if !status.success() || !errors.is_empty() {
            return Err(HostError::Unavailable);
        }
        Ok(output)
    })();
    terminate(&mut child);
    result
}

fn write<W: Write + Send + 'static>(mut output: W, wire: Vec<u8>) -> Receiver<Result<(), ()>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = output.write_all(&wire).map_err(|_| ());
        drop(output);
        let _ = sender.send(result);
    });
    receiver
}

fn reader<R: Read + Send + 'static>(
    mut input: R,
    maximum: usize,
    allow_empty: bool,
) -> Receiver<Result<Vec<u8>, HostError>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut output = Vec::new();
        let read = input
            .by_ref()
            .take(maximum as u64 + 1)
            .read_to_end(&mut output)
            .map_err(|_| HostError::Unavailable);
        let result = match read {
            Err(error) => Err(error),
            Ok(_) if output.len() > maximum || (!allow_empty && output.is_empty()) => {
                Err(HostError::Unavailable)
            }
            Ok(_) => Ok(output),
        };
        let _ = sender.send(result);
    });
    receiver
}

fn receive<T>(value: &Receiver<T>, timeout: Duration) -> Result<T, HostError> {
    value
        .recv_timeout(timeout)
        .map_err(|_| HostError::Unavailable)
}

fn remaining(started: Instant, timeout: Duration) -> Result<Duration, HostError> {
    timeout
        .checked_sub(started.elapsed())
        .filter(|value| !value.is_zero())
        .ok_or(HostError::Unavailable)
}

fn terminate(child: &mut Child) {
    kill_group(child, Signal::SIGTERM);
    let exited = child
        .wait_timeout(Duration::from_millis(100))
        .ok()
        .flatten()
        .is_some();
    if exited {
        kill_group(child, Signal::SIGKILL);
    } else {
        kill_group(child, Signal::SIGKILL);
        let _ = child.wait_timeout(Duration::from_millis(100));
    }
}

fn kill_group(child: &Child, signal: Signal) {
    let group = Pid::from_raw(child.id().try_into().unwrap_or(i32::MAX));
    let _ = killpg(group, signal);
}
