use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::HostError;

pub(crate) fn present(path: &Path) -> Result<bool, HostError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(value) if value.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(HostError::StateInvalid),
    }
}

pub(crate) fn immutable(root: &Path, target: &Path, wire: &[u8]) -> Result<(), HostError> {
    if present(target)? {
        let existing = crate::host_files::owner_file(target, 16_777_216)?;
        return (existing == wire)
            .then_some(())
            .ok_or(HostError::StateInvalid);
    }
    let temporary = temporary(root)?;
    write_new(&temporary, wire)?;
    let result = fs::hard_link(&temporary, target);
    let _ = fs::remove_file(&temporary);
    match result {
        Ok(()) => sync(root),
        Err(value) if value.kind() == ErrorKind::AlreadyExists => {
            let existing = crate::host_files::owner_file(target, 16_777_216)?;
            (existing == wire)
                .then_some(())
                .ok_or(HostError::StateInvalid)
        }
        Err(_) => Err(HostError::StateInvalid),
    }
}

fn write_new(path: &Path, wire: &[u8]) -> Result<(), HostError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| HostError::StateInvalid)?;
    if file.write_all(wire).and_then(|()| file.sync_all()).is_err() {
        let _ = fs::remove_file(path);
        return Err(HostError::StateInvalid);
    }
    Ok(())
}

fn temporary(root: &Path) -> Result<std::path::PathBuf, HostError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostError::StateInvalid)?
        .as_nanos();
    Ok(root.join(format!(".management-v5-{}-{nonce}.tmp", std::process::id())))
}

pub(crate) fn sync(root: &Path) -> Result<(), HostError> {
    File::open(root)
        .and_then(|value| value.sync_all())
        .map_err(|_| HostError::StateInvalid)
}
