use crate::{DeviceId, OpaqueOwnerRef};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepUpProof {
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) device: DeviceId,
    pub(crate) authenticated_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) verified: bool,
}

impl StepUpProof {
    #[must_use]
    pub const fn verified(
        owner: OpaqueOwnerRef,
        device: DeviceId,
        authenticated_at_ms: u64,
        expires_at_ms: u64,
    ) -> Self {
        Self {
            owner,
            device,
            authenticated_at_ms,
            expires_at_ms,
            verified: true,
        }
    }

    #[must_use]
    pub fn owner(&self) -> &OpaqueOwnerRef {
        &self.owner
    }

    #[must_use]
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    #[must_use]
    pub const fn authenticated_at_ms(&self) -> u64 {
        self.authenticated_at_ms
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetKeyProof {
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) device: DeviceId,
    pub(crate) key_thumbprint: String,
    pub(crate) nonce: String,
    pub(crate) issued_at_ms: u64,
    pub(crate) verified: bool,
}

impl TargetKeyProof {
    #[must_use]
    pub fn verified(
        owner: OpaqueOwnerRef,
        device: DeviceId,
        key_thumbprint: impl Into<String>,
        nonce: impl Into<String>,
        issued_at_ms: u64,
    ) -> Self {
        Self {
            owner,
            device,
            key_thumbprint: key_thumbprint.into(),
            nonce: nonce.into(),
            issued_at_ms,
            verified: true,
        }
    }

    #[must_use]
    pub fn owner(&self) -> &OpaqueOwnerRef {
        &self.owner
    }

    #[must_use]
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    #[must_use]
    pub fn key_reference(&self) -> &str {
        &self.key_thumbprint
    }

    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    #[must_use]
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }
}
