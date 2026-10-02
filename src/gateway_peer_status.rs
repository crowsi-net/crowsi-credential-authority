use std::path::PathBuf;

use crate::{
    HostError, gateway_contract::GatewayPeerDocument, gateway_peer_state::PeerStatusEntryV1,
};

#[derive(Clone)]
pub(crate) struct GatewayPeerStatus {
    pub(super) root: PathBuf,
    pub(super) anchor: PathBuf,
    pub(super) peers: Vec<GatewayPeerDocument>,
    pub(super) deployment: String,
    pub(super) authority_epoch: u64,
    pub(super) root_pin: crate::gateway_directory::PinnedDirectory,
    pub(super) anchor_pin: crate::gateway_directory::PinnedDirectory,
}

impl GatewayPeerStatus {}

include!("gateway_peer_status_reconcile.rs");
include!("gateway_peer_status_access.rs");

fn from_remote(
    remote: &crate::gateway_peer_head_types::PeerStatusHeadEntryV1,
    now: u64,
) -> PeerStatusEntryV1 {
    PeerStatusEntryV1 {
        device_id: remote.device_id.clone(),
        certificate_sha256: remote.certificate_sha256.clone(),
        request_key_id: remote.request_key_id.clone(),
        registered: remote.registered,
        revoked: remote.revoked,
        device_revocation_epoch: remote.device_revocation_epoch,
        revoked_at_epoch_s: if remote.revoked { now } else { 0 },
    }
}
