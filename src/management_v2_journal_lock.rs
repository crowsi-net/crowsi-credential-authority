use nix::fcntl::{Flock, FlockArg};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use crate::{HostError, management_v2_journal::ManagementJournalV2};

impl ManagementJournalV2 {
    pub(crate) fn locked<T>(
        &self,
        owner: &str,
        action: impl FnOnce() -> Result<T, HostError>,
    ) -> Result<T, HostError> {
        self.root_pin.validate_source()?;
        self.anchor_pin.validate_source()?;
        self.verify_markers()?;
        let global_path = self.root.join("management-v5-global.lock");
        let global = lock(&global_path)?;
        crate::management_v2_journal_io::validate_layout(&self.root)?;
        self.verify_markers()?;
        let owner_path = self.root.join(format!(
            "management-v5-{}.lock",
            crate::host_crypto::digest(owner.as_bytes())
        ));
        let owner_lock = lock(&owner_path)?;
        let result = action();
        crate::management_v2_journal_io::validate_layout(&self.root)?;
        self.root_pin.validate_source()?;
        self.anchor_pin.validate_source()?;
        drop((owner_lock, global));
        result
    }
}

fn lock(path: &Path) -> Result<Flock<File>, HostError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| HostError::StateInvalid)?;
    let before = file.metadata().map_err(|_| HostError::StateInvalid)?;
    crate::gateway_peer_lock::validate(path, &file, &before)?;
    let lock = Flock::lock(file, FlockArg::LockExclusive).map_err(|_| HostError::StateInvalid)?;
    crate::gateway_peer_lock::validate(path, &lock, &before)?;
    Ok(lock)
}
