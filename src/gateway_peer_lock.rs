use std::{
    fs::{File, Metadata},
    os::unix::fs::MetadataExt,
    path::Path,
};

use crate::HostError;

pub(super) fn validate(path: &Path, file: &File, expected: &Metadata) -> Result<(), HostError> {
    let descriptor = file.metadata().map_err(|_| HostError::StateInvalid)?;
    let linked = std::fs::symlink_metadata(path).map_err(|_| HostError::StateInvalid)?;
    let valid = descriptor.is_file()
        && descriptor.nlink() == 1
        && descriptor.uid() == nix::unistd::geteuid().as_raw()
        && descriptor.mode() & 0o777 == 0o600
        && !linked.file_type().is_symlink()
        && linked.dev() == descriptor.dev()
        && linked.ino() == descriptor.ino()
        && crate::host_open_file::same(expected, &descriptor);
    valid.then_some(()).ok_or(HostError::StateInvalid)
}
