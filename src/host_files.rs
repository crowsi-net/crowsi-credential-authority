use nix::unistd::geteuid;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

use crate::{HostError, host_open_file, host_pinned_file::PinnedFile};

#[cfg(not(feature = "authority-host-test-root"))]
const ROOT_TRUST_PATH: &str = "/etc/crowsi/credential-authority-host/root-trust.json";

pub(crate) fn owner_file(path: &Path, maximum: u64) -> Result<Vec<u8>, HostError> {
    host_open_file::read(path, maximum, geteuid().as_raw(), 0o600)
}

pub(crate) fn pinned_owner_file(
    path: &Path,
    maximum: u64,
    digest: &str,
) -> Result<Vec<u8>, HostError> {
    let wire = owner_file(path, maximum)?;
    if crate::host_crypto::digest(&wire) == digest {
        Ok(wire)
    } else {
        Err(HostError::PathInvalid)
    }
}

pub(crate) fn pin_owner_file(
    path: &Path,
    maximum: u64,
    digest: &str,
) -> Result<PinnedFile, HostError> {
    crate::host_pinned_file::open(path, maximum, digest, geteuid().as_raw(), 0o600, false)
}

pub(crate) fn trusted_executable(path: &Path, digest: &str) -> Result<(), HostError> {
    pin_executable(path, digest).map(|_| ())
}

pub(crate) fn pin_executable(path: &Path, digest: &str) -> Result<PinnedFile, HostError> {
    crate::host_pinned_file::open(path, 134_217_728, digest, geteuid().as_raw(), 0, true)
}

pub(crate) fn owner_directory(path: &Path) -> Result<(), HostError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| HostError::PathInvalid)?;
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
        || fs::canonicalize(path).map_err(|_| HostError::PathInvalid)? != path
    {
        return Err(HostError::PathInvalid);
    }
    Ok(())
}

pub(crate) fn provider_state_directory(path: &Path) -> Result<(), HostError> {
    owner_directory(path)?;
    let before = fs::symlink_metadata(path).map_err(|_| HostError::PathInvalid)?;
    if before.nlink() < 2 {
        return Err(HostError::PathInvalid);
    }
    let effective_uid = geteuid().as_raw();
    let mut parent = path.parent();
    while let Some(value) = parent {
        let metadata = fs::symlink_metadata(value).map_err(|_| HostError::PathInvalid)?;
        let owner = metadata.uid();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (owner != 0 && owner != effective_uid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(HostError::PathInvalid);
        }
        parent = value.parent();
    }
    let after = fs::symlink_metadata(path).map_err(|_| HostError::PathInvalid)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
    {
        return Err(HostError::PathInvalid);
    }
    Ok(())
}

pub(crate) fn root_trust(config: &Path) -> Result<Vec<u8>, HostError> {
    #[cfg(feature = "authority-host-test-root")]
    {
        owner_file(
            &config
                .parent()
                .ok_or(HostError::ConfigInvalid)?
                .join("root-trust.json"),
            16_384,
        )
        .map_err(|_| HostError::ConfigInvalid)
    }
    #[cfg(not(feature = "authority-host-test-root"))]
    {
        let _ = config;
        root_parents()?;
        host_open_file::read(Path::new(ROOT_TRUST_PATH), 16_384, 0, 0)
            .map_err(|_| HostError::ConfigInvalid)
    }
}

#[cfg(not(feature = "authority-host-test-root"))]
fn root_parents() -> Result<(), HostError> {
    for value in [
        "/etc",
        "/etc/crowsi",
        "/etc/crowsi/credential-authority-host",
    ] {
        let path = Path::new(value);
        let metadata = fs::symlink_metadata(path).map_err(|_| HostError::ConfigInvalid)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || fs::canonicalize(path).map_err(|_| HostError::ConfigInvalid)? != path
        {
            return Err(HostError::ConfigInvalid);
        }
    }
    Ok(())
}
