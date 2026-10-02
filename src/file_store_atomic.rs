use crate::{AuthorityError, file_store_path::PinnedDirectory};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn replace(
    root: &PinnedDirectory,
    name: &str,
    label: &str,
    expected: Option<&[u8]>,
    bytes: &[u8],
) -> Result<(), AuthorityError> {
    root.validate_source()?;
    let destination = root.path().join(name);
    match expected {
        Some(value) if crate::file_store_file::read(root, name, value.len() + 1)? != value => {
            return Err(AuthorityError::RollbackDetected);
        }
        Some(_) => {}
        None => match fs::symlink_metadata(&destination) {
            Ok(_) => return Err(AuthorityError::IntegrityViolation),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AuthorityError::StoreUnavailable),
        },
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthorityError::StoreUnavailable)?
        .as_nanos();
    let temporary = root.path().join(format!(
        ".authority-{label}-{}-{nonce}.tmp",
        std::process::id()
    ));
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
    fs::rename(&temporary, &destination).map_err(|_| AuthorityError::StoreUnavailable)?;
    let stored = crate::file_store_file::read(root, name, bytes.len() + 1)?;
    if stored != bytes {
        return Err(AuthorityError::IntegrityViolation);
    }
    crate::file_store_file::sync(root)
}
