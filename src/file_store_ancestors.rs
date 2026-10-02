use crate::AuthorityError;
use nix::unistd::geteuid;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub(crate) fn validate(path: &Path) -> Result<(), AuthorityError> {
    for ancestor in path.ancestors().skip(1) {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| AuthorityError::StorePathInvalid)?;
        let canonical = fs::canonicalize(ancestor).map_err(|_| AuthorityError::StorePathInvalid)?;
        let owner = metadata.uid() == 0 || metadata.uid() == geteuid().as_raw();
        let secure = metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && canonical == ancestor
            && owner
            && metadata.mode() & 0o022 == 0;
        if !secure && !test_temporary_root(ancestor, &metadata) {
            return Err(AuthorityError::StorePathInvalid);
        }
    }
    Ok(())
}

#[cfg(feature = "test-support")]
fn test_temporary_root(path: &Path, metadata: &fs::Metadata) -> bool {
    fs::canonicalize(std::env::temp_dir()).ok().as_deref() == Some(path)
        && metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == 0
        && metadata.mode() & 0o1000 != 0
}

#[cfg(not(feature = "test-support"))]
const fn test_temporary_root(_path: &Path, _metadata: &fs::Metadata) -> bool {
    false
}
