use crowsi_authority_transport::{AuthorityBackend, SignedRequest, TransportError};
use std::sync::Arc;

use crate::{HostError, gateway_host_process::GatewayHostProcess};

pub(crate) struct CredentialAuthorityBackend {
    host: Arc<GatewayHostProcess>,
    peer_status: crate::gateway_peer_status::GatewayPeerStatus,
    gateway: crate::gateway_contract::GatewayConfigDocument,
    host_trust: crate::host_config_types::HostConfigDocument,
}

impl CredentialAuthorityBackend {
    pub(crate) const fn new(
        host: Arc<GatewayHostProcess>,
        peer_status: crate::gateway_peer_status::GatewayPeerStatus,
        gateway: crate::gateway_contract::GatewayConfigDocument,
        host_trust: crate::host_config_types::HostConfigDocument,
    ) -> Self {
        Self {
            host,
            peer_status,
            gateway,
            host_trust,
        }
    }

    pub(crate) fn peer_status(&self) -> crate::gateway_peer_status::GatewayPeerStatus {
        self.peer_status.clone()
    }
}

impl AuthorityBackend for CredentialAuthorityBackend {
    fn handle(&self, request: &SignedRequest) -> Result<Vec<u8>, TransportError> {
        let response = self.host.exchange(request);
        let applied = response.as_ref().map_err(|_| ()).and_then(|wire| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ())?
                .as_secs();
            crate::gateway_peer_response::apply(
                &self.peer_status,
                &self.host_trust,
                request,
                wire,
                now,
            )
            .map_err(|_| ())
        });
        let head = self
            .host
            .peer_status_head(&self.gateway, &self.host_trust)
            .map_err(map)?;
        self.peer_status.reconcile_head(&head).map_err(map)?;
        match (response, applied) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(())) => Err(TransportError::Unavailable),
            (Err(error), _) => Err(map(error)),
        }
    }
}

fn map(value: HostError) -> TransportError {
    match value {
        HostError::RequestInvalid | HostError::OperationInvalid => TransportError::Contract,
        HostError::EvidenceInvalid => TransportError::Peer,
        HostError::ConfigInvalid => TransportError::Config,
        HostError::StateInvalid => TransportError::Replay,
        _ => TransportError::Unavailable,
    }
}
