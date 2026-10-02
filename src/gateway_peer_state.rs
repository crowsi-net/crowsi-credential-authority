use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerDenyLedgerV1 {
    pub(super) schema: String,
    pub(super) revision: u64,
    pub(super) authority_revision: u64,
    pub(super) authority_head_sha256: String,
    pub(super) entries: Vec<PeerStatusEntryV1>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerStatusEntryV1 {
    pub(super) device_id: String,
    pub(super) certificate_sha256: String,
    pub(super) request_key_id: String,
    pub(super) registered: bool,
    pub(super) revoked: bool,
    pub(super) device_revocation_epoch: u64,
    pub(super) revoked_at_epoch_s: u64,
}

impl PeerDenyLedgerV1 {
    pub(super) fn empty() -> Self {
        Self {
            schema: schema().into(),
            revision: 1,
            authority_revision: 0,
            authority_head_sha256: format!("sha256:{}", "0".repeat(64)),
            entries: Vec::new(),
        }
    }
}

pub(super) const fn schema() -> &'static str {
    "crowsi://credential-authority/gateway-peer-status-ledger/v2"
}
