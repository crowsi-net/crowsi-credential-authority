use std::path::Path;

use crate::{
    CoelaAuthorityAdapter, FileAuthorityStore, HostError,
    host_config::{self, VerifiedHostConfig},
    host_identity::{HostIdentityVerifier, HostOwnerMapper},
    host_proofs::HostProofVerifier,
};

pub(crate) type ManagementHostAdapter = CoelaAuthorityAdapter<
    FileAuthorityStore,
    HostIdentityVerifier,
    HostOwnerMapper,
    HostProofVerifier,
>;

pub(crate) struct ManagementHostContext {
    pub(crate) config: VerifiedHostConfig,
}

impl ManagementHostContext {
    pub(crate) fn open_pinned(path: &Path, digest: &str, now: u64) -> Result<Self, HostError> {
        Ok(Self {
            config: host_config::load_pinned(path, digest, now)?,
        })
    }

    pub(crate) fn provider_route(
        &self,
        service: &str,
    ) -> Result<&crate::host_config_types::HostProviderRoute, HostError> {
        self.config
            .document
            .provider_operations
            .iter()
            .find(|item| item.service_id == service)
            .ok_or(HostError::ConfigInvalid)
    }
}
