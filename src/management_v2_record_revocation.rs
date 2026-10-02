#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationSagaV2 {
    pub started: bool,
    pub local_revocation_applied: bool,
    pub rotations: Vec<RevocationRotationV2>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationRotationV2 {
    pub credential_ref: String,
    pub target_device_ref: String,
    pub target_binding: Option<RevocationTargetBindingV1>,
    pub provider_request_id: String,
    pub provider_operation_ref: String,
    pub provider_nonce: String,
    pub attempt_number: u64,
    pub reconcile_sequence: u64,
    pub provider_reconcile_request_id: Option<String>,
    pub attempted: bool,
    pub provider_acceptance:
        Option<crate::management_v2_provider_acceptance::ProviderEvidenceAcceptanceV1>,
    pub prior_acceptances:
        Vec<crate::management_v2_provider_acceptance::ProviderEvidenceAcceptanceV1>,
    pub prior_acceptance_count: u64,
    pub prior_acceptance_digest_sha256: String,
    pub authority_applied: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationTargetBindingV1 {
    pub credential_revision: u64,
    pub service_id: String,
    pub pairwise_subject: String,
    pub issuer: String,
    pub device_proof_key_ref: String,
    pub device_epoch: u64,
    pub posture_state: String,
    pub posture_revision: u64,
    pub subject_epoch: u64,
    pub service_epoch: u64,
    pub session_epoch: u64,
    pub identity_key_id: String,
    pub grants: Vec<RevocationGrantBindingV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationGrantBindingV1 {
    pub grant_id: String,
    pub source_device_ref: String,
    pub target_device_ref: String,
    pub audience: String,
    pub action: String,
    pub credential_revision: u64,
    pub expires_at_ms: u64,
    pub state: String,
}
