use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use std::{fs::File, io::Read, os::fd::AsRawFd, path::Path};

use crate::{HostError, host_open_file};

pub(crate) struct PinnedFile {
    file: File,
    proc_path: String,
}

impl PinnedFile {
    pub(crate) fn path(&self) -> &str {
        &self.proc_path
    }
    pub(crate) fn retain(&self) -> &File {
        &self.file
    }
}

pub(crate) fn open(
    path: &Path,
    maximum: u64,
    digest: &str,
    uid: u32,
    mode: u32,
    executable: bool,
) -> Result<PinnedFile, HostError> {
    let (file, before) = host_open_file::open(path, maximum, uid, mode, executable)?;
    let mut wire = Vec::new();
    (&file)
        .take(maximum + 1)
        .read_to_end(&mut wire)
        .map_err(|_| HostError::PathInvalid)?;
    let after = file.metadata().map_err(|_| HostError::PathInvalid)?;
    if !host_open_file::same(&before, &after) || crate::host_crypto::digest(&wire) != digest {
        return Err(HostError::PathInvalid);
    }
    fcntl(file.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty()))
        .map_err(|_| HostError::PathInvalid)?;
    let proc_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    Ok(PinnedFile { file, proc_path })
}
