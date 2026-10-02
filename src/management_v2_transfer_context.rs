use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferContextV2 {
    pub transfer_id: String,
    pub owner_ref: String,
    pub target_device_ref: String,
    pub target_key_ref: String,
    pub target_nonce: String,
    pub target_proof_issued_at_ms: u64,
    pub service_id: String,
    pub credential_ref: String,
    pub provider_operation_ref: String,
    pub provider_nonce: String,
    pub reconcile_sequence: u64,
    pub provider_reconcile_request_id: Option<String>,
}

impl TransferContextV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        transfer: &crate::TransferId,
        owner: &crate::OpaqueOwnerRef,
        target: &crate::TargetKeyProof,
        service: &str,
        credential: &str,
        provider_operation: &str,
        provider_nonce: &str,
    ) -> Self {
        Self {
            transfer_id: transfer.as_str().into(),
            owner_ref: owner.as_str().into(),
            target_device_ref: target.device().as_str().into(),
            target_key_ref: target.key_reference().into(),
            target_nonce: target.nonce().into(),
            target_proof_issued_at_ms: target.issued_at_ms(),
            service_id: service.into(),
            credential_ref: credential.into(),
            provider_operation_ref: provider_operation.into(),
            provider_nonce: provider_nonce.into(),
            reconcile_sequence: 0,
            provider_reconcile_request_id: None,
        }
    }
}
