use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, ManagementProjectionBodyV2, canonical_management_projection,
    identity_evidence_from_exchange,
};

use crate::{HostError, management_v2_handler::ManagementV2Handler};

impl ManagementV2Handler {
    pub(crate) fn recover_cancel_response(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        peer: &str,
        now: u64,
    ) -> Result<Option<Vec<u8>>, HostError> {
        let Some(recovery) = self.journal.cancel_recovery_view(envelope, peer, now)? else {
            return Ok(None);
        };
        if recovery.current_snapshot_revision == recovery.accepted_snapshot_revision
            && current_response(&self.core.config, &recovery.original_response, now)?
        {
            return serde_json::to_vec(&recovery.original_response)
                .map(Some)
                .map_err(|_| HostError::ResponseInvalid);
        }
        let identity = identity_evidence_from_exchange(&recovery.identity_exchange)
            .map_err(|_| HostError::StateInvalid)?;
        crate::management_v2_projection::signed(
            &self.core.config,
            &envelope.browser_request,
            identity,
            &recovery.owner_ref,
            recovery.current_snapshot_revision,
            ManagementProjectionBodyV2::Operation {
                operation: recovery.operation,
            },
            now,
        )
        .map(Some)
    }
}

pub(crate) fn current_response(
    config: &crate::host_config::VerifiedHostConfig,
    value: &crowsi_credential_authority_contracts::ManagementProjectionV2,
    now: u64,
) -> Result<bool, HostError> {
    let canonical = canonical_management_projection(value).map_err(|_| HostError::StateInvalid)?;
    Ok(value.key_id == config.document.management_projection_key_id
        && value.issuer == config.document.management_projection_issuer
        && value.audience == config.document.management_audience
        && now >= value.issued_at_epoch_s
        && now < value.expires_at_epoch_s
        && crate::host_crypto::verify(
            &config.document.management_projection_public_key_hex,
            &value.signature,
            &canonical,
        ))
}
