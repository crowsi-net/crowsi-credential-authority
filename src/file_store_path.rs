use crate::AuthorityError;
use nix::unistd::geteuid;
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug)]
pub(crate) struct StorePaths {
    pub state: PinnedDirectory,
    pub anchor: PinnedDirectory,
}

#[derive(Clone, Debug)]
pub(crate) struct PinnedDirectory {
    file: Arc<File>,
    source: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
}

impl StorePaths {
    pub(crate) fn prepare(state: &Path, anchor: &Path) -> Result<Self, AuthorityError> {
        let state = PinnedDirectory::open(state)?;
        let anchor = PinnedDirectory::open(anchor)?;
        if state.source == anchor.source
            || (state.device == anchor.device && state.inode == anchor.inode)
        {
            return Err(AuthorityError::StorePathInvalid);
        }
        let value = Self { state, anchor };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), AuthorityError> {
        self.state.validate_source()?;
        self.anchor.validate_source()
    }
}

impl PinnedDirectory {
    fn open(path: &Path) -> Result<Self, AuthorityError> {
        validate_absolute(path)?;
        crate::file_store_ancestors::validate(path)?;
        let before = fs::symlink_metadata(path).map_err(|_| AuthorityError::StorePathInvalid)?;
        let canonical = fs::canonicalize(path).map_err(|_| AuthorityError::StorePathInvalid)?;
        if canonical != path || !valid_directory(&before) {
            return Err(AuthorityError::StorePathInvalid);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| AuthorityError::StorePathInvalid)?;
        let after = file
            .metadata()
            .map_err(|_| AuthorityError::StorePathInvalid)?;
        if !crate::file_store_metadata::same(&before, &after) || !valid_directory(&after) {
            return Err(AuthorityError::StorePathInvalid);
        }
        let value = Self {
            device: after.dev(),
            inode: after.ino(),
            uid: after.uid(),
            mode: after.mode(),
            links: after.nlink(),
            file: Arc::new(file),
            source: path.to_owned(),
        };
        value.validate_source()?;
        Ok(value)
    }

    pub(crate) fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn source(&self) -> &Path {
        &self.source
    }

    pub(crate) fn validate_source(&self) -> Result<(), AuthorityError> {
        crate::file_store_ancestors::validate(&self.source)?;
        let linked =
            fs::symlink_metadata(&self.source).map_err(|_| AuthorityError::StorePathInvalid)?;
        let opened = self
            .file
            .metadata()
            .map_err(|_| AuthorityError::StorePathInvalid)?;
        if matches_expected(&linked, self)
            && matches_expected(&opened, self)
            && crate::file_store_metadata::same(&linked, &opened)
        {
            Ok(())
        } else {
            Err(AuthorityError::StorePathInvalid)
        }
    }
}

fn validate_absolute(path: &Path) -> Result<(), AuthorityError> {
    let clean = path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir));
    clean.then_some(()).ok_or(AuthorityError::StorePathInvalid)
}

fn valid_directory(value: &fs::Metadata) -> bool {
    value.is_dir()
        && !value.file_type().is_symlink()
        && value.uid() == geteuid().as_raw()
        && value.mode() & 0o7777 == 0o700
}

fn matches_expected(value: &fs::Metadata, expected: &PinnedDirectory) -> bool {
    valid_directory(value)
        && value.dev() == expected.device
        && value.ino() == expected.inode
        && value.uid() == expected.uid
        && value.mode() == expected.mode
        && value.nlink() == expected.links
}
