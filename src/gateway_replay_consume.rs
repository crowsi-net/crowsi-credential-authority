use crowsi_authority_transport::{ReplayGuard, TransportError};

use crate::{
    gateway_replay::GatewayReplayGuard,
    gateway_replay_state::{
        GLOBAL_REPLAY_CAPACITY, PER_DEVICE_REPLAY_CAPACITY, REPLAY_TTL_SECONDS, ReplayEntry,
        now_epoch_s,
    },
};

impl ReplayGuard for GatewayReplayGuard {
    fn consume(&self, device: &str, nonce: &str, digest: &str) -> Result<(), TransportError> {
        self.preflight(device, nonce)?;
        if let Some(authority) = &self.authority {
            authority
                .consume(device, nonce, digest)
                .map_err(map_authority)?;
        }
        self.commit(device, nonce, digest)
    }
}

impl GatewayReplayGuard {
    fn preflight(&self, device: &str, nonce: &str) -> Result<(), TransportError> {
        self.locked(|| {
            let now = now_epoch_s()?;
            let mut value = self.read()?;
            prune(&mut value, now)?;
            available(&value, device, nonce)
        })
    }

    fn commit(&self, device: &str, nonce: &str, digest: &str) -> Result<(), TransportError> {
        self.locked(|| {
            let now = now_epoch_s()?;
            let mut value = self.read()?;
            prune(&mut value, now)?;
            available(&value, device, nonce)?;
            value.entries.push(ReplayEntry {
                device_id: device.into(),
                nonce: nonce.into(),
                request_digest: digest.into(),
                consumed_at_epoch_s: now,
            });
            value.revision = value
                .revision
                .checked_add(1)
                .ok_or(TransportError::Unavailable)?;
            self.write(&value)
        })
    }
}

fn prune(
    value: &mut crate::gateway_replay_state::ReplayLedger,
    now: u64,
) -> Result<(), TransportError> {
    if value
        .entries
        .iter()
        .any(|item| item.consumed_at_epoch_s > now)
    {
        return Err(TransportError::Unavailable);
    }
    value
        .entries
        .retain(|item| now.saturating_sub(item.consumed_at_epoch_s) <= REPLAY_TTL_SECONDS);
    Ok(())
}

fn available(
    value: &crate::gateway_replay_state::ReplayLedger,
    device: &str,
    nonce: &str,
) -> Result<(), TransportError> {
    if value
        .entries
        .iter()
        .any(|item| item.device_id == device && item.nonce == nonce)
    {
        return Err(TransportError::Replay);
    }
    let full = value.entries.len() >= GLOBAL_REPLAY_CAPACITY
        || value
            .entries
            .iter()
            .filter(|item| item.device_id == device)
            .count()
            >= PER_DEVICE_REPLAY_CAPACITY;
    (!full).then_some(()).ok_or(TransportError::Unavailable)
}

fn map_authority(value: crate::HostError) -> TransportError {
    match value {
        crate::HostError::EvidenceInvalid => TransportError::Replay,
        crate::HostError::RequestInvalid | crate::HostError::ResponseInvalid => {
            TransportError::Contract
        }
        crate::HostError::ConfigInvalid => TransportError::Config,
        _ => TransportError::Unavailable,
    }
}
