use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Projection {
    pub schema_id: String,
    #[serde(rename = "revocation_epoch")]
    pub _revocation_epoch: u64,
    pub credentials: Vec<Credential>,
    pub devices: Vec<Device>,
    pub sessions: Vec<Session>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credential {
    pub credential_id: String,
    pub service_id: String,
    #[serde(rename = "provider_account_ref")]
    pub _provider_account_ref: String,
    #[serde(rename = "alias")]
    pub _alias: String,
    pub class: String,
    pub revision: u64,
    pub revoked: bool,
    pub assigned_device_ids: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at_epoch_ms: u64,
    pub updated_at_epoch_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Device {
    pub device_id: String,
    #[serde(rename = "service_id")]
    pub _service_id: String,
    #[serde(rename = "device_proof_key_ref")]
    pub _device_proof_key_ref: String,
    #[serde(rename = "posture_state")]
    pub _posture_state: String,
    pub posture_revision: u64,
    pub device_revocation_epoch: u64,
    pub enrolled_at_epoch_ms: u64,
    pub last_seen_at_epoch_ms: u64,
    pub revoked: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Session {
    pub session_ref: String,
    pub device_id: String,
    pub session_revocation_epoch: u64,
    pub issued_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
    #[serde(rename = "last_seen_at_epoch_ms")]
    pub _last_seen_at_epoch_ms: u64,
    pub revoked: bool,
}
