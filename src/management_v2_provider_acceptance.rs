use serde::{Deserialize, Serialize};

use crate::{
    CredentialId, DeviceId, HostError, OpaqueOwnerRef, ProviderOperationOutcome,
    ProviderReissueReceipt, SignedProviderReconciliation, host_config_types::HostProviderRoute,
    host_provider_contract::HostProviderEvidence,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderEvidenceAcceptanceV1 {
    pub document: HostProviderEvidence,
    pub document_sha256: String,
    pub response_key_id: String,
    pub response_public_key_hex: String,
    pub accepted_at_epoch_s: u64,
}

impl ProviderEvidenceAcceptanceV1 {
    pub(crate) fn current(
        document: HostProviderEvidence,
        route: &HostProviderRoute,
        now: u64,
    ) -> Result<Self, HostError> {
        Ok(Self {
            document_sha256: digest(&document)?,
            document,
            response_key_id: route.response_key_id.clone(),
            response_public_key_hex: route.response_public_key_hex.clone(),
            accepted_at_epoch_s: now,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), HostError> {
        let exact = self.document_sha256 == digest(&self.document)?
            && self.document.key_id == self.response_key_id
            && self.document.issued_at_epoch_s <= self.accepted_at_epoch_s
            && self.accepted_at_epoch_s > 0;
        exact.then_some(()).ok_or(HostError::EvidenceInvalid)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn accept_receipt(
    document: HostProviderEvidence,
    route: &HostProviderRoute,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
    target: &DeviceId,
    nonce: &str,
    now: u64,
    reconciled: bool,
) -> Result<(ProviderEvidenceAcceptanceV1, ProviderReissueReceipt), HostError> {
    let receipt = if reconciled {
        crate::host_provider_evidence::historic_receipt(
            &document,
            &route.response_key_id,
            &route.response_public_key_hex,
            owner,
            credential,
            target,
            nonce,
            now,
        )?
    } else {
        crate::host_provider_evidence::receipt(
            &document, route, owner, credential, target, nonce, now,
        )?
    };
    Ok((
        ProviderEvidenceAcceptanceV1::current(document, route, now)?,
        receipt,
    ))
}

pub(crate) fn historic_receipt(
    value: &ProviderEvidenceAcceptanceV1,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
    target: &DeviceId,
    nonce: &str,
    now: u64,
) -> Result<ProviderReissueReceipt, HostError> {
    value.validate()?;
    crate::host_provider_evidence::historic_receipt(
        &value.document,
        &value.response_key_id,
        &value.response_public_key_hex,
        owner,
        credential,
        target,
        nonce,
        now,
    )
}

pub(crate) fn accept_unknown(
    document: HostProviderEvidence,
    route: &HostProviderRoute,
    operation: &str,
    nonce: &str,
    now: u64,
) -> Result<(ProviderEvidenceAcceptanceV1, ProviderOperationOutcome), HostError> {
    let outcome = crate::host_provider_evidence::unknown(&document, route, operation, nonce, now)?;
    Ok((
        ProviderEvidenceAcceptanceV1::current(document, route, now)?,
        outcome,
    ))
}

pub(crate) fn accept_reconciliation(
    document: HostProviderEvidence,
    route: &HostProviderRoute,
    operation: &str,
    nonce: &str,
    now: u64,
) -> Result<(ProviderEvidenceAcceptanceV1, SignedProviderReconciliation), HostError> {
    let signed = crate::host_provider_evidence::historic_reconciliation(
        &document,
        &route.response_key_id,
        &route.response_public_key_hex,
        operation,
        nonce,
        now,
    )?;
    Ok((
        ProviderEvidenceAcceptanceV1::current(document, route, now)?,
        signed,
    ))
}

include!("management_v2_provider_acceptance_historic.rs");
