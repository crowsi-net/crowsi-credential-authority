use crate::AuthorityError;
use nix::unistd::geteuid;
use std::{
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::Path,
};

pub(crate) fn valid(value: &fs::Metadata) -> bool {
    value.is_file()
        && !value.file_type().is_symlink()
        && value.uid() == geteuid().as_raw()
        && value.mode() & 0o7777 == 0o600
        && value.nlink() == 1
}

pub(crate) fn validate_open(
    path: &Path,
    file: &File,
    expected: &fs::Metadata,
) -> Result<(), AuthorityError> {
    let opened = file
        .metadata()
        .map_err(|_| AuthorityError::StoreUnavailable)?;
    let linked = fs::symlink_metadata(path).map_err(|_| AuthorityError::StoreUnavailable)?;
    if valid(&opened) && same(expected, &opened) && same(&opened, &linked) {
        Ok(())
    } else {
        Err(AuthorityError::IntegrityViolation)
    }
}

pub(crate) fn same(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.gid() == right.gid()
        && left.rdev() == right.rdev()
        && left.len() == right.len()
        && left.blocks() == right.blocks()
        && left.blksize() == right.blksize()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
