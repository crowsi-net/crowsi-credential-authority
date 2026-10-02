use crate::{
    AuthorityError,
    file_store_failpoint::{FileStoreFailpoint, hit},
    file_store_head::{HEAD_NAME, MAX_HEAD_BYTES},
    file_store_path::{PinnedDirectory, StorePaths},
};

pub(crate) fn write(paths: &StorePaths, wire: &[u8]) -> Result<(), AuthorityError> {
    let state = head(&paths.state)?;
    let anchor = head(&paths.anchor)?;
    if anchor.is_some() && state.is_none() {
        return Err(AuthorityError::IntegrityViolation);
    }
    write_one(&paths.state, "state-head", state.as_deref(), wire)?;
    hit(FileStoreFailpoint::StateHeadWritten)?;
    write_one(&paths.anchor, "anchor-head", anchor.as_deref(), wire)?;
    hit(FileStoreFailpoint::AnchorHeadWritten)
}

pub(crate) fn head_present(paths: &StorePaths) -> Result<bool, AuthorityError> {
    Ok(present(&paths.state, HEAD_NAME)? || present(&paths.anchor, HEAD_NAME)?)
}

pub(crate) fn both_present(paths: &StorePaths) -> Result<bool, AuthorityError> {
    Ok(present(&paths.state, HEAD_NAME)? && present(&paths.anchor, HEAD_NAME)?)
}

pub(crate) fn present(root: &PinnedDirectory, name: &str) -> Result<bool, AuthorityError> {
    match std::fs::symlink_metadata(root.path().join(name)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(AuthorityError::StoreUnavailable),
    }
}

fn write_one(
    root: &PinnedDirectory,
    label: &str,
    existing: Option<&[u8]>,
    expected: &[u8],
) -> Result<(), AuthorityError> {
    match existing {
        Some(value) if value == expected => Ok(()),
        Some(_) => Err(AuthorityError::IntegrityViolation),
        None => crate::file_store_atomic::replace(root, HEAD_NAME, label, None, expected),
    }
}

fn head(root: &PinnedDirectory) -> Result<Option<Vec<u8>>, AuthorityError> {
    if present(root, HEAD_NAME)? {
        crate::file_store_file::read(root, HEAD_NAME, MAX_HEAD_BYTES).map(Some)
    } else {
        Ok(None)
    }
}
