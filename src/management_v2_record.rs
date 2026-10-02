use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementOperationV2, RevocationIndependentCeremonyV1,
    RevocationSourceCeremonyV1, SignedAuthorityExchangeV1, SignedTargetDeviceProofV2,
};
use ihat_identity_assertion_contracts::{
    AuthorityResult, FreshUvV1, IdentityEvidenceMetadata, ResponseOutcome,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagementRecordV2 {
    pub operation: ManagementOperationV2,
    pub prepared: EndpointPreparedOperationV2,
    pub owner_ref: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub authority_config_generation: u64,
    pub source_identity_exchange: SignedAuthorityExchangeV1,
    pub source_options_exchange: SignedAuthorityExchangeV1,
    pub actor_options_identity_exchange: Option<SignedAuthorityExchangeV1>,
    pub actor_options_exchange: Option<SignedAuthorityExchangeV1>,
    pub source_finish_uv_exchange: Option<SignedAuthorityExchangeV1>,
    pub source_approval_identity_exchange: Option<SignedAuthorityExchangeV1>,
    pub source_approval_acceptance_sha256: Option<String>,
    pub target_finish_uv_exchange: Option<SignedAuthorityExchangeV1>,
    pub independent_finish_uv_exchange: Option<SignedAuthorityExchangeV1>,
    pub target_identity_exchange: Option<SignedAuthorityExchangeV1>,
    pub independent_identity_exchange: Option<SignedAuthorityExchangeV1>,
    pub target_proof: Option<SignedTargetDeviceProofV2>,
    pub approved_by_device_ref: Option<String>,
    pub provider_transfer_id: Option<String>,
    pub grant_action: Option<String>,
    pub source_revocation_ceremony: Option<RevocationSourceCeremonyV1>,
    pub revocation_finalization: Option<Box<RevocationFinalizationAcceptanceV1>>,
    pub independent_revocation_finalization:
        Option<Box<IndependentRevocationFinalizationAcceptanceV1>>,
    pub independent_revocation_ceremony: Option<RevocationIndependentCeremonyV1>,
    pub transfer_context: Option<crate::management_v2_transfer_context::TransferContextV2>,
    pub transfer_provider_acceptance:
        Option<crate::management_v2_provider_acceptance::ProviderEvidenceAcceptanceV1>,
    pub transfer_provider_history:
        Vec<crate::management_v2_provider_acceptance::ProviderEvidenceAcceptanceV1>,
    pub transfer_provider_history_count: u64,
    pub transfer_provider_history_digest_sha256: String,
    pub revocation_saga: Option<RevocationSagaV2>,
}

include!("management_v2_record_finalization.rs");

impl ManagementRecordV2 {
    pub(crate) fn source_identity(&self) -> Result<&IdentityEvidenceMetadata, crate::HostError> {
        crowsi_credential_authority_contracts::identity_evidence_from_exchange(
            &self.source_identity_exchange,
        )
        .map_err(|_| crate::HostError::StateInvalid)
    }

    pub(crate) fn target_identity(
        &self,
    ) -> Result<Option<&IdentityEvidenceMetadata>, crate::HostError> {
        self.target_identity_exchange
            .as_ref()
            .map(crowsi_credential_authority_contracts::identity_evidence_from_exchange)
            .transpose()
            .map_err(|_| crate::HostError::StateInvalid)
    }

    pub(crate) fn source_fresh_uv(&self) -> Result<&FreshUvV1, crate::HostError> {
        let value = self
            .source_finish_uv_exchange
            .as_ref()
            .ok_or(crate::HostError::EvidenceInvalid)?;
        let ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvFinished { document },
        } = &value.response.outcome
        else {
            return Err(crate::HostError::EvidenceInvalid);
        };
        Ok(document)
    }
}

include!("management_v2_record_revocation.rs");

include!("management_v2_record_ledger.rs");
