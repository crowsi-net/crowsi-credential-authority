#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationExecutionCancellationAcceptanceV1 {
    pub accepted_at_epoch_s: u64,
    pub outer_key_id: String,
    pub outer_public_key_hex: String,
    pub outer_config_generation: u64,
    pub cancellation_key_id: String,
    pub cancellation_public_key_hex: String,
    pub cancellation_config_generation: u64,
    pub cancellation_request_sha256: String,
    pub cancellation_request:
        Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelRequestV1>,
    pub cancellation:
        Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationV1>,
    pub cleanup_exchange:
        Option<crowsi_credential_authority_contracts::SignedAuthorityExchangeV1>,
    pub cleanup_accepted_at_epoch_s: Option<u64>,
    pub cleanup_outer_key_id: Option<String>,
    pub cleanup_outer_public_key_hex: Option<String>,
    pub cleanup_outer_config_generation: Option<u64>,
    pub cleanup_request_sha256: Option<String>,
    pub cleanup_request: Option<
        Box<
            crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelFinalizeRequestV1,
        >,
    >,
    pub cleanup:
        Option<Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupV1>>,
    pub cleanup_delivery_accepted_at_epoch_s: Option<u64>,
    pub cleanup_delivery_outer_key_id: Option<String>,
    pub cleanup_delivery_outer_public_key_hex: Option<String>,
    pub cleanup_delivery_outer_config_generation: Option<u64>,
    pub cleanup_delivery_acknowledge_key_id: Option<String>,
    pub cleanup_delivery_acknowledge_public_key_hex: Option<String>,
    pub cleanup_delivery_acknowledge_minimum_config_generation: Option<u64>,
    pub cleanup_delivery_request_sha256: Option<String>,
    pub cleanup_delivery_request: Option<
        Box<
            crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
        >,
    >,
    pub cleanup_delivery: Option<
        Box<
            crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupCompleteV1,
        >,
    >,
}
