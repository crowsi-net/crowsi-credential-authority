use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostRootTrust {
    pub schema: String,
    pub configuration_key_id: String,
    pub configuration_public_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostOwnerMapping {
    pub issuer: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub opaque_owner_ref: String,
    pub account_binding_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostDeviceKey {
    pub opaque_owner_ref: String,
    pub device_id: String,
    pub device_proof_key_ref: String,
    pub public_key_hex: String,
    pub custody: String,
    pub custody_revision: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostProviderRoute {
    pub service_id: String,
    pub executable: String,
    pub executable_sha256: String,
    pub config_path: String,
    pub config_sha256: String,
    pub state_directory: String,
    pub response_key_id: String,
    pub response_public_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostConfigDocument {
    pub schema: String,
    pub deployment_role: String,
    pub authority_store_directory: String,
    pub authority_anchor_directory: String,
    pub operation_state_directory: String,
    pub management_state_directory: String,
    pub management_anchor_directory: String,
    pub response_signing_key_path: String,
    pub response_key_id: String,
    pub response_public_key_hex: String,
    pub identity_issuer: String,
    pub registration_audience: String,
    pub management_audience: String,
    pub management_projection_issuer: String,
    pub management_projection_signing_key_path: String,
    pub management_projection_key_id: String,
    pub management_projection_public_key_hex: String,
    pub revocation_execution_reservation_signing_key_path: String,
    pub revocation_execution_reservation_key_id: String,
    pub revocation_execution_reservation_public_key_hex: String,
    pub revocation_execution_reservation_config_generation: u64,
    pub identity_key_id: String,
    pub identity_public_key_hex: String,
    pub current_status_key_id: String,
    pub current_status_public_key_hex: String,
    pub user_verification_key_id: String,
    pub user_verification_public_key_hex: String,
    pub identity_response_key_id: String,
    pub identity_response_public_key_hex: String,
    pub minimum_identity_config_generation: u64,
    pub identity_finalization_authority_id: String,
    pub revocation_approval_authority_refs: Vec<String>,
    pub provider_operations: Vec<HostProviderRoute>,
    pub owner_mappings: Vec<HostOwnerMapping>,
    pub device_proof_keys: Vec<HostDeviceKey>,
    pub authority_epoch: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub configuration_key_id: String,
    pub signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostSigningKeyDocument {
    pub schema: String,
    pub key_id: String,
    pub private_key_hex: zeroize::Zeroizing<String>,
}
