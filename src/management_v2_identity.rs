use crowsi_credential_authority_contracts::{
    EndpointIdentityTrustV2, EndpointManagementEnvelopeV2, EndpointManagementEvidenceV2,
    EndpointPreparedOperationV2, ManagementCommandV2, ManagementIntentV2,
    SignedAuthorityExchangeV1, identity_evidence_from_exchange, verify_endpoint_identity_at,
};
use ihat_identity_assertion_contracts::IdentityEvidenceMetadata;

use crate::{HostError, host_config::VerifiedHostConfig, host_config_types::HostOwnerMapping};

pub(crate) struct VerifiedManagementIdentity<'a> {
    pub identity_exchange: &'a SignedAuthorityExchangeV1,
    pub identity: &'a IdentityEvidenceMetadata,
    pub owner: &'a HostOwnerMapping,
}

pub(crate) fn verify<'a>(
    config: &'a VerifiedHostConfig,
    envelope: &'a EndpointManagementEnvelopeV2,
    peer_device: &str,
    now: u64,
) -> Result<VerifiedManagementIdentity<'a>, HostError> {
    let (identity_exchange, prepared) = evidence(&envelope.evidence);
    crate::management_v2_evidence::verify_exchange(
        config,
        identity_exchange,
        "issue_current_device_identity_evidence",
        now,
    )?;
    let identity = identity_evidence_from_exchange(identity_exchange)
        .map_err(|_| HostError::EvidenceInvalid)?;
    let service = request_service(&envelope.browser_request.command, prepared)?;
    let allow_historic_prepared = matches!(
        envelope.browser_request.command,
        ManagementCommandV2::Cancel { .. } | ManagementCommandV2::Reconcile { .. }
    );
    verify_actor(
        config,
        identity_exchange,
        identity,
        peer_device,
        service,
        now,
        prepared,
        allow_historic_prepared,
    )
}

pub(crate) fn verify_lookup<'a>(
    config: &'a VerifiedHostConfig,
    identity_exchange: &'a SignedAuthorityExchangeV1,
    peer_device: &str,
    now: u64,
) -> Result<VerifiedManagementIdentity<'a>, HostError> {
    crate::management_v2_evidence::verify_exchange(
        config,
        identity_exchange,
        "issue_current_device_identity_evidence",
        now,
    )?;
    let identity = identity_evidence_from_exchange(identity_exchange)
        .map_err(|_| HostError::EvidenceInvalid)?;
    let service = identity.assertion.service_id.as_str();
    verify_actor(
        config,
        identity_exchange,
        identity,
        peer_device,
        service,
        now,
        None,
        false,
    )
}

pub(crate) fn verify_direct<'a>(
    config: &'a VerifiedHostConfig,
    identity_exchange: &'a SignedAuthorityExchangeV1,
    peer_device: &str,
    prepared: &'a EndpointPreparedOperationV2,
    allow_historic_prepared: bool,
    now: u64,
) -> Result<VerifiedManagementIdentity<'a>, HostError> {
    crate::management_v2_evidence::verify_exchange(
        config,
        identity_exchange,
        "issue_current_device_identity_evidence",
        now,
    )?;
    let identity = identity_evidence_from_exchange(identity_exchange)
        .map_err(|_| HostError::EvidenceInvalid)?;
    verify_actor(
        config,
        identity_exchange,
        identity,
        peer_device,
        intent_service(&prepared.intent),
        now,
        Some(prepared),
        allow_historic_prepared,
    )
}

include!("management_v2_identity_validation.rs");
