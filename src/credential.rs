use crate::{CredentialId, OpaqueOwnerRef, ProviderAccountRef, ServiceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum CredentialClass {
    OperationOnly,
    DelegatedToken,
    Certificate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRegistration {
    pub(crate) id: CredentialId,
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) service: ServiceId,
    pub(crate) provider_account: ProviderAccountRef,
    pub(crate) alias: String,
    pub(crate) class: CredentialClass,
    pub(crate) revision: u64,
}

impl CredentialRegistration {
    #[must_use]
    pub fn metadata_only(
        id: CredentialId,
        owner: OpaqueOwnerRef,
        service: ServiceId,
        provider_account: ProviderAccountRef,
        alias: impl Into<String>,
        class: CredentialClass,
        revision: u64,
    ) -> Self {
        Self {
            id,
            owner,
            service,
            provider_account,
            alias: alias.into(),
            class,
            revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMetadata {
    pub(crate) id: CredentialId,
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) service: ServiceId,
    pub(crate) provider_account: ProviderAccountRef,
    pub(crate) alias: String,
    pub(crate) class: CredentialClass,
    pub(crate) revision: u64,
    pub(crate) revoked: bool,
    pub(crate) created_at_ms: u64,
    pub(crate) updated_at_ms: u64,
}

impl CredentialMetadata {
    #[must_use]
    pub const fn contains_secret_values(&self) -> bool {
        false
    }

    #[must_use]
    pub fn owner(&self) -> &OpaqueOwnerRef {
        &self.owner
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn from_registration(value: CredentialRegistration, now_ms: u64) -> Self {
        Self {
            id: value.id,
            owner: value.owner,
            service: value.service,
            provider_account: value.provider_account,
            alias: value.alias,
            class: value.class,
            revision: value.revision,
            revoked: false,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        }
    }
}
