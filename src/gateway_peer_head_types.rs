use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerStatusHeadRequestV1 {
    pub(super) schema: String,
    pub(super) request_id: String,
    pub(super) deployment_id: String,
    pub(super) gateway_config_sha256: String,
    pub(super) authority_epoch: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerStatusHeadEntryV1 {
    pub(super) device_id: String,
    pub(super) certificate_sha256: String,
    pub(super) request_key_id: String,
    pub(super) registered: bool,
    pub(super) revoked: bool,
    pub(super) device_revocation_epoch: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerStatusHeadV1 {
    pub(super) schema: String,
    pub(super) request_id: String,
    pub(super) request_digest_sha256: String,
    pub(super) deployment_id: String,
    pub(super) gateway_config_sha256: String,
    pub(super) authority_epoch: u64,
    pub(super) authority_revision: u64,
    pub(super) entries: Vec<PeerStatusHeadEntryV1>,
    pub(super) head_digest_sha256: String,
    pub(super) issued_at_epoch_s: u64,
    pub(super) expires_at_epoch_s: u64,
    pub(super) key_id: String,
    pub(super) signature: String,
}

pub(super) const REQUEST_SCHEMA: &str = "crowsi://credential-authority/peer-status-head-request/v1";
pub(super) const RESPONSE_SCHEMA: &str = "crowsi://credential-authority/peer-status-head/v1";
pub(super) const RESPONSE_DOMAIN: &str = "CROWSI-CREDENTIAL-AUTHORITY-PEER-STATUS-HEAD-V1";
