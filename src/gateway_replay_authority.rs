use std::sync::Arc;

use crate::{
    HostError, gateway_contract::GatewayConfigDocument, gateway_host_process::GatewayHostProcess,
    host_config_types::HostConfigDocument,
};

#[derive(Clone)]
pub(super) struct GatewayReplayAuthority {
    process: Arc<GatewayHostProcess>,
    gateway: GatewayConfigDocument,
    host: HostConfigDocument,
}

impl GatewayReplayAuthority {
    pub(super) const fn new(
        process: Arc<GatewayHostProcess>,
        gateway: GatewayConfigDocument,
        host: HostConfigDocument,
    ) -> Self {
        Self {
            process,
            gateway,
            host,
        }
    }

    pub(super) fn consume(&self, device: &str, nonce: &str, digest: &str) -> Result<(), HostError> {
        self.process
            .consume_transport_replay(&self.gateway, &self.host, device, nonce, digest)
    }
}
