use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, identity_evidence_from_exchange,
};

use crate::{HostError, management_v2_handler::ManagementV2Handler};

impl ManagementV2Handler {
    pub(crate) fn recover_mutation_response(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        peer: &str,
        now: u64,
    ) -> Result<Option<Vec<u8>>, HostError> {
        let Some(recovery) = self.journal.mutation_recovery_view(envelope, peer, now)? else {
            return Ok(None);
        };
        let identity = identity_evidence_from_exchange(&recovery.identity_exchange)
            .map_err(|_| HostError::StateInvalid)?;
        if !self.core.config.document.owner_mappings.iter().any(|item| {
            item.issuer == identity.assertion.issuer
                && item.service_id == identity.assertion.service_id
                && item.pairwise_subject == identity.assertion.pairwise_subject
                && item.opaque_owner_ref == recovery.owner_ref
        }) {
            return Err(HostError::StateInvalid);
        }
        if recovery.current_snapshot_revision == recovery.accepted_snapshot_revision
            && recovery.current_generation_head == recovery.accepted_generation_head
            && crate::management_v2_cancel_recovery::current_response(
                &self.core.config,
                &recovery.original_response,
                now,
            )?
        {
            return serde_json::to_vec(&recovery.original_response)
                .map(Some)
                .map_err(|_| HostError::ResponseInvalid);
        }
        crate::management_v2_projection::signed(
            &self.core.config,
            &envelope.browser_request,
            identity,
            &recovery.owner_ref,
            recovery.current_snapshot_revision,
            recovery.original_response.body,
            now,
        )
        .map(Some)
    }
}
