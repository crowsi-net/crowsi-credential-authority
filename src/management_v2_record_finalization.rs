#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationFinalizationAcceptanceV1 {
    pub accepted_at_epoch_s: u64,
    pub pre_final_state_revision: u64,
    pub pre_final_snapshot_revision: u64,
    pub source_approve_request_sha256: String,
    pub reconcile_digest: String,
    pub source_approve_request: crowsi_credential_authority_contracts::ManagementRequestV2,
    pub accepted_identity_exchange: SignedAuthorityExchangeV1,
    pub begin_exchange: SignedAuthorityExchangeV1,
    pub response_key_id: String,
    pub response_public_key_hex: String,
    pub minimum_config_generation: u64,
    pub cancellation_slot_reserved: bool,
    pub cancellation_cleanup_completed: bool,
    pub cancellation_cleanup_delivery_completed: bool,
    pub cancellation_recovery_reservation_bytes: u64,
    pub execution_reservation: Option<RevocationExecutionReservationAcceptanceV1>,
    pub execution_cancellation: Option<RevocationExecutionCancellationAcceptanceV1>,
    pub finalize_request_sha256: Option<String>,
    pub finalize_request:
        Option<Box<crowsi_credential_authority_contracts::EndpointRevocationFinalizeRequestV1>>,
    pub final_revoke_exchange: Option<SignedAuthorityExchangeV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IndependentRevocationFinalizationAcceptanceV1 {
    pub accepted_at_epoch_s: u64,
    pub pre_final_state_revision: u64,
    pub pre_final_snapshot_revision: u64,
    pub pre_final_request_sha256: String,
    pub reconcile_digest: String,
    pub pre_final_request:
        Box<crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1>,
    pub accepted_identity_exchange: SignedAuthorityExchangeV1,
    pub selected_identity_exchange: SignedAuthorityExchangeV1,
    pub begin_uv_exchange: SignedAuthorityExchangeV1,
    pub finish_uv_exchange: SignedAuthorityExchangeV1,
    pub begin_exchange: SignedAuthorityExchangeV1,
    pub approval_exchange: SignedAuthorityExchangeV1,
    pub response_key_id: String,
    pub response_public_key_hex: String,
    pub minimum_config_generation: u64,
    pub cancellation_slot_reserved: bool,
    pub cancellation_cleanup_completed: bool,
    pub cancellation_cleanup_delivery_completed: bool,
    pub cancellation_recovery_reservation_bytes: u64,
    pub execution_reservation: Option<RevocationExecutionReservationAcceptanceV1>,
    pub execution_cancellation: Option<RevocationExecutionCancellationAcceptanceV1>,
    pub finalize_request_sha256: Option<String>,
    pub finalize_request: Option<
        Box<crowsi_credential_authority_contracts::EndpointIndependentRevocationFinalizeRequestV1>,
    >,
    pub final_revoke_exchange: Option<SignedAuthorityExchangeV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationExecutionReservationAcceptanceV1 {
    pub accepted_at_epoch_s: u64,
    pub outer_key_id: String,
    pub outer_public_key_hex: String,
    pub outer_config_generation: u64,
    pub reservation_key_id: String,
    pub reservation_public_key_hex: String,
    pub reservation_config_generation: u64,
    pub reservation_request_sha256: String,
    pub reservation_request:
        Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1>,
    pub reservation:
        Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationV1>,
}

include!("management_v2_record_cancellation.rs");
