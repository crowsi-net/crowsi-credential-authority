use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostProviderEvidence {
    pub schema: String,
    pub kind: String,
    pub key_id: String,
    pub signature: String,
    pub nonce: String,
    pub issued_at_epoch_s: u64,
    pub receipt_id: Option<String>,
    pub operation_ref: Option<String>,
    pub owner_ref: Option<String>,
    pub service_id: Option<String>,
    pub provider_account_ref: Option<String>,
    pub credential_ref: Option<String>,
    pub previous_revision: Option<u64>,
    pub revision: Option<u64>,
    pub target_device_ref: Option<String>,
}

impl HostProviderEvidence {
    pub(crate) fn exact_shape(&self) -> bool {
        let receipt = (
            self.receipt_id.is_some(),
            self.operation_ref.is_some(),
            self.owner_ref.is_some(),
            self.service_id.is_some(),
            self.provider_account_ref.is_some(),
            self.credential_ref.is_some(),
            self.previous_revision.is_some(),
            self.revision.is_some(),
            self.target_device_ref.is_some(),
        );
        match self.kind.as_str() {
            "reissue-receipt" => receipt == (true, false, true, true, true, true, true, true, true),
            "unknown-outcome" | "not-issued-reconciliation" => {
                receipt == (false, true, false, false, false, false, false, false, false)
            }
            _ => false,
        }
    }
}
