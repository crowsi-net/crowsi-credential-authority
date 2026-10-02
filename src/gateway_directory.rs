use std::{
    fs::{self, File, OpenOptions},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::HostError;

#[derive(Clone)]
pub(super) struct PinnedDirectory {
    file: Arc<File>,
    source: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
}

impl PinnedDirectory {
    pub(super) fn open(path: &Path) -> Result<Self, HostError> {
        crate::host_files::owner_directory(path)?;
        let before = fs::symlink_metadata(path).map_err(|_| HostError::PathInvalid)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| HostError::PathInvalid)?;
        let after = file.metadata().map_err(|_| HostError::PathInvalid)?;
        if !same(&before, &after) {
            return Err(HostError::PathInvalid);
        }
        let value = Self {
            device: after.dev(),
            inode: after.ino(),
            uid: after.uid(),
            mode: after.mode(),
            links: after.nlink(),
            file: Arc::new(file),
            source: path.into(),
        };
        value.validate_source()?;
        Ok(value)
    }

    pub(super) fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    pub(super) fn validate_source(&self) -> Result<(), HostError> {
        let value = fs::symlink_metadata(&self.source).map_err(|_| HostError::StateInvalid)?;
        let opened = self.file.metadata().map_err(|_| HostError::StateInvalid)?;
        let valid = valid(&value, self) && valid(&opened, self);
        valid.then_some(()).ok_or(HostError::StateInvalid)
    }
}

fn valid(value: &fs::Metadata, expected: &PinnedDirectory) -> bool {
    !value.file_type().is_symlink()
        && value.is_dir()
        && value.dev() == expected.device
        && value.ino() == expected.inode
        && value.uid() == expected.uid
        && value.mode() == expected.mode
        && value.mode() & 0o777 == 0o700
        && value.nlink() == expected.links
}

fn same(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
}
