use crowsi_authority_transport::TransportError;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplayEntry {
    pub(super) device_id: String,
    pub(super) nonce: String,
    pub(super) request_digest: String,
    pub(super) consumed_at_epoch_s: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplayLedger {
    pub(super) schema: String,
    pub(super) revision: u64,
    pub(super) entries: Vec<ReplayEntry>,
}

impl ReplayLedger {
    pub(super) fn empty() -> Self {
        Self {
            schema: schema().into(),
            revision: 1,
            entries: Vec::new(),
        }
    }
}

pub(super) const fn schema() -> &'static str {
    "crowsi://credential-authority/gateway-replay/v2"
}

pub(super) fn now_epoch_s() -> Result<u64, TransportError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| TransportError::Unavailable)
}

pub(super) const REPLAY_TTL_SECONDS: u64 = 300;
pub(super) const PER_DEVICE_REPLAY_CAPACITY: usize = 256;
pub(super) const GLOBAL_REPLAY_CAPACITY: usize = 100_000;
