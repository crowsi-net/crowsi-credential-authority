use crate::{CredentialId, DeviceId, OpaqueOwnerRef, ProviderAccountRef, ServiceId};
use sha2::{Digest, Sha256};

pub(crate) fn provider_operation_ref(target_nonce: &str) -> String {
    format!(
        "provider-{}",
        hex::encode(Sha256::digest(target_nonce.as_bytes()))
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReissueReceipt {
    pub(crate) receipt_id: String,
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) service: ServiceId,
    pub(crate) provider_account: ProviderAccountRef,
    pub(crate) credential_id: CredentialId,
    pub(crate) previous_revision: u64,
    pub(crate) revision: u64,
    pub(crate) target_device: DeviceId,
    pub(crate) nonce: String,
    pub(crate) issued_at_ms: u64,
    pub(crate) signature: String,
    signed_revision: u64,
    signed_target: DeviceId,
}

impl ProviderReissueReceipt {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn signed(
        receipt_id: impl Into<String>,
        owner: OpaqueOwnerRef,
        service: ServiceId,
        provider_account: ProviderAccountRef,
        credential_id: CredentialId,
        previous_revision: u64,
        revision: u64,
        target_device: DeviceId,
        nonce: impl Into<String>,
        issued_at_ms: u64,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            owner,
            service,
            provider_account,
            credential_id,
            previous_revision,
            revision,
            signed_revision: revision,
            signed_target: target_device.clone(),
            target_device,
            nonce: nonce.into(),
            issued_at_ms,
            signature: signature.into(),
        }
    }

    pub fn with_revision(mut self, revision: u64) -> Self {
        self.revision = revision;
        self
    }

    pub fn with_target_device(mut self, target: DeviceId) -> Self {
        self.target_device = target;
        self
    }

    pub(crate) fn signature_intact(&self) -> bool {
        self.revision == self.signed_revision && self.target_device == self.signed_target
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderOperationOutcome {
    pub(crate) operation_id: String,
    pub(crate) nonce: String,
    pub(crate) signature: String,
    pub(crate) issued_at_ms: u64,
}

impl ProviderOperationOutcome {
    #[must_use]
    pub fn unknown_signed(
        operation_id: impl Into<String>,
        nonce: impl Into<String>,
        signature: impl Into<String>,
        issued_at_ms: u64,
    ) -> Self {
        Self {
            operation_id: operation_id.into(),
            nonce: nonce.into(),
            signature: signature.into(),
            issued_at_ms,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedProviderReconciliation {
    pub(crate) operation_id: String,
    pub(crate) nonce: String,
    pub(crate) signature: String,
    pub(crate) issued_at_ms: u64,
    pub(crate) was_issued: bool,
}

impl SignedProviderReconciliation {
    #[must_use]
    pub fn not_issued(
        operation_id: impl Into<String>,
        nonce: impl Into<String>,
        signature: impl Into<String>,
        issued_at_ms: u64,
    ) -> Self {
        Self {
            operation_id: operation_id.into(),
            nonce: nonce.into(),
            signature: signature.into(),
            issued_at_ms,
            was_issued: false,
        }
    }
}
