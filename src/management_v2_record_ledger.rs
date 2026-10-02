#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagementLedgerV2 {
    pub schema: String,
    pub revision: u64,
    pub authority_config_generation_head: u64,
    pub consumed_evidence: Vec<ConsumedEvidenceV2>,
    pub transport_replays: Vec<TransportReplayV1>,
    pub durable_responses: Vec<DurableResponseReceiptV1>,
    pub records: Vec<ManagementRecordV2>,
    pub tombstones: Vec<ManagementTombstoneV2>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "response_kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DurableResponseV1 {
    Projection(Box<crowsi_credential_authority_contracts::ManagementProjectionV2>),
    PreparedLookup(Box<crowsi_credential_authority_contracts::EndpointPreparedLookupResponseV1>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableResponseReceiptV1 {
    pub request_digest_sha256: String,
    pub identity_exchange_sha256: String,
    pub actor_device_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    pub read_only: bool,
    pub operation_id: Option<String>,
    pub accepted_ledger_revision: u64,
    pub accepted_generation_head: u64,
    pub retain_until_epoch_s: u64,
    pub response: DurableResponseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagementTombstoneV2 {
    pub operation: ManagementOperationV2,
    pub prepared: EndpointPreparedOperationV2,
    pub owner_ref: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub source_identity_exchange_sha256: String,
    pub source_options_exchange_sha256: String,
    pub revocation_finalization: Option<Box<RevocationFinalizationAcceptanceV1>>,
    pub independent_revocation_finalization:
        Option<Box<IndependentRevocationFinalizationAcceptanceV1>>,
    pub authority_config_generation: u64,
}

impl ManagementTombstoneV2 {
    pub(crate) fn from_record(value: &ManagementRecordV2) -> Result<Self, crate::HostError> {
        Ok(Self {
            operation: value.operation.clone(),
            prepared: value.prepared.clone(),
            owner_ref: value.owner_ref.clone(),
            service_id: value.service_id.clone(),
            pairwise_subject: value.pairwise_subject.clone(),
            authority_config_generation: value.authority_config_generation,
            source_identity_exchange_sha256: crate::management_v2_journal_policy::exchange_digest(
                &value.source_identity_exchange,
            )?,
            source_options_exchange_sha256: crate::management_v2_journal_policy::exchange_digest(
                &value.source_options_exchange,
            )?,
            revocation_finalization: value.revocation_finalization.clone(),
            independent_revocation_finalization: value.independent_revocation_finalization.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumedEvidenceV2 {
    pub digest: String,
    pub binding_sha256: String,
    pub expires_at_epoch_s: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransportReplayV1 {
    pub device_id: String,
    pub digest: String,
    pub expires_at_epoch_s: u64,
}

impl ManagementLedgerV2 {
    pub(crate) fn empty() -> Self {
        Self {
            schema: schema().into(),
            revision: 1,
            authority_config_generation_head: 1,
            consumed_evidence: Vec::new(),
            transport_replays: Vec::new(),
            durable_responses: Vec::new(),
            records: Vec::new(),
            tombstones: Vec::new(),
        }
    }
}

pub(crate) const fn schema() -> &'static str {
    "crowsi://credential-authority/management-ledger/v17"
}
