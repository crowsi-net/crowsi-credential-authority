use crowsi_authority_transport::TransportError;
use nix::fcntl::{Flock, FlockArg};
use std::{
    fs::OpenOptions,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub struct GatewayReplayGuard {
    pub(super) root: PathBuf,
    pub(super) anchor: PathBuf,
    pub(super) deployment: String,
    pub(super) authority_epoch: u64,
    pub(super) root_pin: crate::gateway_directory::PinnedDirectory,
    pub(super) anchor_pin: crate::gateway_directory::PinnedDirectory,
    pub(super) authority: Option<crate::gateway_replay_authority::GatewayReplayAuthority>,
}

impl GatewayReplayGuard {
    pub fn initialize(
        root: &Path,
        anchor: &Path,
        deployment: &str,
        authority_epoch: u64,
    ) -> Result<(), TransportError> {
        let value = Self::value(root, anchor, deployment, authority_epoch)?;
        value.locked(|| {
            crate::gateway_replay_io::initialize(
                &value.root,
                &value.anchor,
                &value.deployment,
                value.authority_epoch,
            )
            .map_err(|_| TransportError::Unavailable)
        })
    }

    #[cfg(feature = "test-support")]
    pub fn open(
        root: &Path,
        anchor: &Path,
        deployment: &str,
        authority_epoch: u64,
    ) -> Result<Self, TransportError> {
        let value = Self::value(root, anchor, deployment, authority_epoch)?;
        value.locked(|| value.read().map(|_| ()))?;
        Ok(value)
    }

    pub(crate) fn open_with_authority(
        root: &Path,
        anchor: &Path,
        deployment: &str,
        authority_epoch: u64,
        authority: crate::gateway_replay_authority::GatewayReplayAuthority,
    ) -> Result<Self, TransportError> {
        let mut value = Self::value(root, anchor, deployment, authority_epoch)?;
        value.locked(|| value.read().map(|_| ()))?;
        value.authority = Some(authority);
        Ok(value)
    }

    fn value(
        root: &Path,
        anchor: &Path,
        deployment: &str,
        epoch: u64,
    ) -> Result<Self, TransportError> {
        if deployment.is_empty() || epoch == 0 {
            return Err(TransportError::Config);
        }
        let root_pin = crate::gateway_directory::PinnedDirectory::open(root)
            .map_err(|_| TransportError::Config)?;
        let anchor_pin = crate::gateway_directory::PinnedDirectory::open(anchor)
            .map_err(|_| TransportError::Config)?;
        Ok(Self {
            root: root_pin.path(),
            anchor: anchor_pin.path(),
            deployment: deployment.into(),
            authority_epoch: epoch,
            root_pin,
            anchor_pin,
            authority: None,
        })
    }

    pub(super) fn locked<T>(
        &self,
        action: impl FnOnce() -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        self.root_pin
            .validate_source()
            .map_err(|_| TransportError::Unavailable)?;
        self.anchor_pin
            .validate_source()
            .map_err(|_| TransportError::Unavailable)?;
        let path = self.root.join("transport-replay.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| TransportError::Unavailable)?;
        let before = file.metadata().map_err(|_| TransportError::Unavailable)?;
        crate::gateway_peer_lock::validate(&path, &file, &before)
            .map_err(|_| TransportError::Unavailable)?;
        let guard =
            Flock::lock(file, FlockArg::LockExclusive).map_err(|_| TransportError::Unavailable)?;
        crate::gateway_peer_lock::validate(&path, &guard, &before)
            .map_err(|_| TransportError::Unavailable)?;
        let result = action();
        self.root_pin
            .validate_source()
            .map_err(|_| TransportError::Unavailable)?;
        self.anchor_pin
            .validate_source()
            .map_err(|_| TransportError::Unavailable)?;
        result
    }

    pub(super) fn read(&self) -> Result<crate::gateway_replay_state::ReplayLedger, TransportError> {
        crate::gateway_replay_io::read(
            &self.root,
            &self.anchor,
            &self.deployment,
            self.authority_epoch,
        )
        .map_err(|_| TransportError::Unavailable)
    }

    pub(super) fn write(
        &self,
        value: &crate::gateway_replay_state::ReplayLedger,
    ) -> Result<(), TransportError> {
        crate::gateway_replay_io::write(
            &self.root,
            &self.anchor,
            &self.deployment,
            self.authority_epoch,
            value,
        )
        .map_err(|_| TransportError::Unavailable)
    }
}
