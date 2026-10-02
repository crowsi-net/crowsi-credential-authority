use nix::fcntl::{Flock, FlockArg};
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};

use crate::{
    HostError, gateway_contract::GatewayPeerDocument, gateway_peer_status::GatewayPeerStatus,
};

impl GatewayPeerStatus {
    pub(crate) fn initialize(
        root: &Path,
        anchor: &Path,
        deployment: &str,
        authority_epoch: u64,
        peers: &[GatewayPeerDocument],
    ) -> Result<(), HostError> {
        let value = Self::value(root, anchor, deployment, authority_epoch, peers)?;
        value.locked(|| {
            crate::gateway_peer_state_io::initialize(
                &value.root,
                &value.anchor,
                &value.deployment,
                value.authority_epoch,
            )
        })
    }

    pub(crate) fn open(
        root: &Path,
        anchor: &Path,
        deployment: &str,
        authority_epoch: u64,
        peers: &[GatewayPeerDocument],
    ) -> Result<Self, HostError> {
        let value = Self::value(root, anchor, deployment, authority_epoch, peers)?;
        value.locked(|| value.read_ledger().map(|_| ()))?;
        Ok(value)
    }

    fn value(
        root: &Path,
        anchor: &Path,
        deployment: &str,
        authority_epoch: u64,
        peers: &[GatewayPeerDocument],
    ) -> Result<Self, HostError> {
        if deployment.is_empty() || authority_epoch == 0 {
            return Err(HostError::ConfigInvalid);
        }
        let root_pin = crate::gateway_directory::PinnedDirectory::open(root)?;
        let anchor_pin = crate::gateway_directory::PinnedDirectory::open(anchor)?;
        Ok(Self {
            root: root_pin.path(),
            anchor: anchor_pin.path(),
            peers: peers.to_vec(),
            deployment: deployment.into(),
            authority_epoch,
            root_pin,
            anchor_pin,
        })
    }

    pub(super) fn locked<T>(
        &self,
        action: impl FnOnce() -> Result<T, HostError>,
    ) -> Result<T, HostError> {
        self.root_pin.validate_source()?;
        self.anchor_pin.validate_source()?;
        let path = self.root.join("gateway-peer-status.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| HostError::StateInvalid)?;
        let before = file.metadata().map_err(|_| HostError::StateInvalid)?;
        crate::gateway_peer_lock::validate(&path, &file, &before)?;
        let guard =
            Flock::lock(file, FlockArg::LockExclusive).map_err(|_| HostError::StateInvalid)?;
        crate::gateway_peer_lock::validate(&path, &guard, &before)?;
        let result = action();
        self.root_pin.validate_source()?;
        self.anchor_pin.validate_source()?;
        result
    }

    pub(super) fn read_ledger(
        &self,
    ) -> Result<crate::gateway_peer_state::PeerDenyLedgerV1, HostError> {
        let ledger = crate::gateway_peer_state_io::read(
            &self.root,
            &self.anchor,
            &self.deployment,
            self.authority_epoch,
        )?;
        let valid = ledger.entries.iter().all(|entry| {
            self.peers.iter().any(|peer| {
                peer.device_id == entry.device_id
                    && peer.certificate_sha256 == entry.certificate_sha256
                    && peer.request_key_id == entry.request_key_id
            })
        });
        valid.then_some(ledger).ok_or(HostError::StateInvalid)
    }
}
