use crate::{DeviceId, OpaqueOwnerRef};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionRecord {
    pub owner: OpaqueOwnerRef,
    pub device_id: DeviceId,
    pub session_ref: String,
    pub epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub last_seen_at_ms: u64,
    pub revoked: bool,
}
