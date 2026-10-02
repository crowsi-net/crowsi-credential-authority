use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplayWitnessRequestV1 {
    pub(super) schema: String,
    pub(super) request_id: String,
    pub(super) deployment_id: String,
    pub(super) gateway_config_sha256: String,
    pub(super) authority_epoch: u64,
    pub(super) device_id: String,
    pub(super) nonce: String,
    pub(super) transport_request_digest: String,
    pub(super) expires_at_epoch_s: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplayWitnessResponseV1 {
    pub(super) schema: String,
    pub(super) request_id: String,
    pub(super) request_digest_sha256: String,
    pub(super) deployment_id: String,
    pub(super) gateway_config_sha256: String,
    pub(super) authority_epoch: u64,
    pub(super) device_id: String,
    pub(super) nonce: String,
    pub(super) transport_request_digest: String,
    pub(super) witness_revision: u64,
    pub(super) issued_at_epoch_s: u64,
    pub(super) expires_at_epoch_s: u64,
    pub(super) key_id: String,
    pub(super) signature: String,
}

pub(super) const REQUEST_SCHEMA: &str =
    "crowsi://credential-authority/transport-replay-witness-request/v1";
pub(super) const RESPONSE_SCHEMA: &str =
    "crowsi://credential-authority/transport-replay-witness/v1";
pub(super) const RESPONSE_DOMAIN: &str = "CROWSI-CREDENTIAL-AUTHORITY-TRANSPORT-REPLAY-WITNESS-V1";
