use crate::{AuthorityError, file_store_path::StorePaths};
use nix::fcntl::{Flock, FlockArg};
use std::{
    fs::{self, File, OpenOptions},
    io::ErrorKind,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(crate) const LOCK_NAME: &str = "authority.lock";

pub(crate) struct StoreLock {
    file: Flock<File>,
    path: PathBuf,
    device: u64,
    inode: u64,
    paths: StorePaths,
}

impl StoreLock {
    pub(crate) fn open(paths: &StorePaths, exclusive: bool) -> Result<Self, AuthorityError> {
        Self::open_mode(paths, exclusive, false)
    }

    pub(crate) fn initialize(paths: &StorePaths) -> Result<Self, AuthorityError> {
        Self::open_mode(paths, true, true)
    }

    fn open_mode(
        paths: &StorePaths,
        exclusive: bool,
        initialize: bool,
    ) -> Result<Self, AuthorityError> {
        paths.validate()?;
        let path = paths.state.path().join(LOCK_NAME);
        let file = if initialize {
            open_or_create(&path, crate::file_store_inventory::empty(paths)?)?
        } else {
            open_existing(&path)?
        };
        let metadata = file
            .metadata()
            .map_err(|_| AuthorityError::StoreUnavailable)?;
        validate(&path, &file, metadata.dev(), metadata.ino())?;
        let argument = if exclusive {
            FlockArg::LockExclusive
        } else {
            FlockArg::LockShared
        };
        let file = Flock::lock(file, argument).map_err(|_| AuthorityError::StoreUnavailable)?;
        let value = Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            file,
            path,
            paths: paths.clone(),
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), AuthorityError> {
        self.paths.validate()?;
        validate(&self.path, &self.file, self.device, self.inode)
    }
}

fn open_or_create(path: &Path, may_create: bool) -> Result<File, AuthorityError> {
    if !may_create {
        return open_existing(path);
    }
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => open_existing(path),
        Err(_) => Err(AuthorityError::StoreUnavailable),
    }
}

fn open_existing(path: &Path) -> Result<File, AuthorityError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| AuthorityError::StoreUnavailable)
}

fn validate(path: &Path, file: &File, device: u64, inode: u64) -> Result<(), AuthorityError> {
    let opened = file
        .metadata()
        .map_err(|_| AuthorityError::StoreUnavailable)?;
    let linked = fs::symlink_metadata(path).map_err(|_| AuthorityError::StoreUnavailable)?;
    let valid = crate::file_store_metadata::valid(&opened)
        && crate::file_store_metadata::same(&opened, &linked)
        && opened.dev() == device
        && opened.ino() == inode;
    valid
        .then_some(())
        .ok_or(AuthorityError::IntegrityViolation)
}
