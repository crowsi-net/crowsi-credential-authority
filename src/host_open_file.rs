use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use crate::HostError;

pub(crate) fn read(
    path: &Path,
    maximum: u64,
    uid: u32,
    exact_mode: u32,
) -> Result<Vec<u8>, HostError> {
    let (file, before) = open(path, maximum, uid, exact_mode, false)?;
    let mut wire = Vec::new();
    (&file)
        .take(maximum + 1)
        .read_to_end(&mut wire)
        .map_err(|_| HostError::PathInvalid)?;
    let after = file.metadata().map_err(|_| HostError::PathInvalid)?;
    if !same(&before, &after) || wire.len() < 2 || wire.len() as u64 > maximum {
        return Err(HostError::PathInvalid);
    }
    Ok(wire)
}

pub(crate) fn open(
    path: &Path,
    maximum: u64,
    uid: u32,
    exact_mode: u32,
    executable: bool,
) -> Result<(File, fs::Metadata), HostError> {
    if !path.is_absolute()
        || (!pinned_descendant(path)
            && fs::canonicalize(path).map_err(|_| HostError::PathInvalid)? != path)
    {
        return Err(HostError::PathInvalid);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| HostError::PathInvalid)?;
    let metadata = file.metadata().map_err(|_| HostError::PathInvalid)?;
    let owner = metadata.uid() == uid || (executable && metadata.uid() == 0);
    let mode = metadata.mode() & 0o777;
    let permission = if executable {
        mode & 0o022 == 0 && mode & 0o111 != 0
    } else if exact_mode == 0 {
        mode & 0o022 == 0
    } else {
        mode == exact_mode
    };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || !owner
        || !permission
        || !(2..=maximum).contains(&metadata.len())
    {
        return Err(HostError::PathInvalid);
    }
    Ok((file, metadata))
}

fn pinned_descendant(path: &Path) -> bool {
    let mut values = path.components();
    matches!(values.next(), Some(std::path::Component::RootDir))
        && values
            .next()
            .is_some_and(|value| value.as_os_str() == "proc")
        && values
            .next()
            .is_some_and(|value| value.as_os_str() == "self")
        && values.next().is_some_and(|value| value.as_os_str() == "fd")
        && values
            .next()
            .and_then(|value| value.as_os_str().to_str())
            .is_some_and(|value| {
                !value.is_empty() && value.bytes().all(|item| item.is_ascii_digit())
            })
        && values.next().is_some()
        && values.all(|value| !matches!(value, std::path::Component::ParentDir))
}

pub(crate) fn same(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}
