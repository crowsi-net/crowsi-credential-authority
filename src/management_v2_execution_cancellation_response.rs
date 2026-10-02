use crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationV1;

use crate::{HostError, host_config::VerifiedHostConfig};

pub(crate) fn refresh(
    config: &VerifiedHostConfig,
    stored: &EndpointRevocationExecutionCancellationV1,
    snapshot_revision: u64,
    now: u64,
) -> Result<Vec<u8>, HostError> {
    if stored.issuer != config.document.management_projection_issuer
        || stored.audience != config.document.management_audience
        || stored.cancellation_config_generation
            != config
                .document
                .revocation_execution_reservation_config_generation
        || stored.token.key_id != config.document.revocation_execution_reservation_key_id
    {
        return Err(HostError::ConfigInvalid);
    }
    let mut value = stored.clone();
    value.snapshot_revision = snapshot_revision;
    value.config_generation = value.cancellation_config_generation;
    value.issued_at_epoch_s = now;
    value.expires_at_epoch_s = now.saturating_add(30);
    value
        .key_id
        .clone_from(&config.document.management_projection_key_id);
    value.signature.clear();
    let canonical = crowsi_credential_authority_contracts::canonical_endpoint_revocation_execution_cancellation(&value)
        .map_err(|_| HostError::ResponseInvalid)?;
    value.signature =
        crate::host_crypto::sign(&config.management_projection_signing_key, &canonical);
    let wire = serde_json::to_vec(&value).map_err(|_| HostError::ResponseInvalid)?;
    (wire.len() <= 262_144)
        .then_some(wire)
        .ok_or(HostError::ResponseInvalid)
}
