use crowsi_authority_transport::{PeerStatusGuard, PeerStatusIdentity, TransportError};

use crate::{HostError, gateway_peer_status::GatewayPeerStatus};

#[derive(Clone)]
pub(crate) struct GatewayPeerGuard {
    status: GatewayPeerStatus,
    authority_epoch: u64,
}

impl GatewayPeerGuard {
    pub(crate) const fn new(status: GatewayPeerStatus, authority_epoch: u64) -> Self {
        Self {
            status,
            authority_epoch,
        }
    }
}

impl PeerStatusGuard for GatewayPeerGuard {
    fn authorize_current(
        &self,
        peer: PeerStatusIdentity<'_>,
        authority_epoch: u64,
    ) -> Result<(), TransportError> {
        if authority_epoch != self.authority_epoch {
            return Err(TransportError::Unavailable);
        }
        match self.status.allows(
            peer.device_id,
            peer.client_certificate_sha256,
            peer.request_key_id,
        ) {
            Ok(true) => Ok(()),
            Ok(false) | Err(HostError::EvidenceInvalid) => Err(TransportError::Peer),
            Err(_) => Err(TransportError::Unavailable),
        }
    }
}
