use crate::{AuthorityError, file_store_path::PinnedDirectory};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn read(
    root: &PinnedDirectory,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, AuthorityError> {
    root.validate_source()?;
    let path = root.path().join(name);
    let before = fs::symlink_metadata(&path).map_err(|_| AuthorityError::StoreUnavailable)?;
    if !crate::file_store_metadata::valid(&before)
        || before.len() == 0
        || before.len() > maximum as u64
    {
        return Err(size_or_integrity(&before, maximum));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|_| AuthorityError::StoreUnavailable)?;
    crate::file_store_metadata::validate_open(&path, &file, &before)?;
    let capacity = usize::try_from(before.len()).map_err(|_| AuthorityError::SnapshotTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthorityError::StoreUnavailable)?;
    let after = file
        .metadata()
        .map_err(|_| AuthorityError::StoreUnavailable)?;
    crate::file_store_metadata::validate_open(&path, &file, &before)?;
    root.validate_source()?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || bytes.len() as u64 != after.len()
        || !crate::file_store_metadata::same(&before, &after)
    {
        return Err(AuthorityError::SnapshotTooLarge);
    }
    Ok(bytes)
}

pub(crate) fn write_immutable(
    root: &PinnedDirectory,
    name: &str,
    label: &str,
    bytes: &[u8],
) -> Result<(), AuthorityError> {
    root.validate_source()?;
    let destination = root.path().join(name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => return exact_existing(root, name, bytes),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(AuthorityError::StoreUnavailable),
    }
    let temporary = temporary(root, label)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| AuthorityError::StoreUnavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| AuthorityError::StoreUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| AuthorityError::StoreUnavailable)?;
    if !crate::file_store_metadata::valid(&metadata) || metadata.len() != bytes.len() as u64 {
        return Err(AuthorityError::IntegrityViolation);
    }
    let result = fs::hard_link(&temporary, &destination);
    let _ = fs::remove_file(&temporary);
    match result {
        Ok(()) => {
            let destination_meta =
                fs::symlink_metadata(&destination).map_err(|_| AuthorityError::StoreUnavailable)?;
            if !crate::file_store_metadata::valid(&destination_meta) {
                return Err(AuthorityError::IntegrityViolation);
            }
            root.validate_source()
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => exact_existing(root, name, bytes),
        Err(_) => Err(AuthorityError::StoreUnavailable),
    }
}

pub(crate) fn remove(root: &PinnedDirectory, name: &str) -> Result<(), AuthorityError> {
    let path = root.path().join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|_| AuthorityError::StoreUnavailable)?;
    if !crate::file_store_metadata::valid(&metadata) {
        return Err(AuthorityError::IntegrityViolation);
    }
    fs::remove_file(path).map_err(|_| AuthorityError::StoreUnavailable)?;
    root.validate_source()
}

pub(crate) fn sync(root: &PinnedDirectory) -> Result<(), AuthorityError> {
    root.validate_source()?;
    File::open(root.path())
        .and_then(|value| value.sync_all())
        .map_err(|_| AuthorityError::StoreUnavailable)?;
    root.validate_source()
}

fn exact_existing(
    root: &PinnedDirectory,
    name: &str,
    expected: &[u8],
) -> Result<(), AuthorityError> {
    let actual = read(root, name, expected.len().saturating_add(1))?;
    (actual == expected)
        .then_some(())
        .ok_or(AuthorityError::IntegrityViolation)
}

fn temporary(root: &PinnedDirectory, label: &str) -> Result<PathBuf, AuthorityError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthorityError::StoreUnavailable)?
        .as_nanos();
    Ok(root.path().join(format!(
        ".authority-{label}-{}-{nonce}.tmp",
        std::process::id()
    )))
}

fn size_or_integrity(value: &fs::Metadata, maximum: usize) -> AuthorityError {
    if value.len() == 0 || value.len() > maximum as u64 {
        AuthorityError::SnapshotTooLarge
    } else {
        AuthorityError::IntegrityViolation
    }
}
