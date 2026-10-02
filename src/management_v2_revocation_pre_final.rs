use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, ManagementProjectionBodyV2, identity_evidence_from_exchange,
};

use crate::{HostError, management_v2_handler::ManagementV2Handler};

impl ManagementV2Handler {
    pub(crate) fn recover_revocation_pre_final(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        peer: &str,
        now: u64,
    ) -> Result<Option<Vec<u8>>, HostError> {
        let Some((ledger_revision, record)) = self
            .journal
            .revocation_pre_final_view(envelope, peer, now)?
        else {
            return Ok(None);
        };
        let acceptance = record
            .revocation_finalization
            .as_ref()
            .ok_or(HostError::StateInvalid)?;
        if !crate::management_v2_historic_mapping::current(
            &self.core.config,
            &acceptance.accepted_identity_exchange,
            &record.owner_ref,
            peer,
        ) {
            return Err(HostError::EvidenceInvalid);
        }
        let identity = identity_evidence_from_exchange(&acceptance.accepted_identity_exchange)
            .map_err(|_| HostError::StateInvalid)?;
        if ledger_revision == acceptance.pre_final_snapshot_revision {
            let request_digest = crate::management_v2_journal_policy::envelope_digest(envelope)?;
            let identity_digest = crate::management_v2_journal_policy::exchange_digest(
                &acceptance.accepted_identity_exchange,
            )?;
            match self.journal.exact_response(
                &record.owner_ref,
                &request_digest,
                &identity_digest,
                acceptance
                    .accepted_identity_exchange
                    .response
                    .config_generation,
                now,
            ) {
                Ok(Some(response)) => return Ok(Some(response)),
                Ok(None) | Err(HostError::StateInvalid) => {}
                Err(error) => return Err(error),
            }
        }
        crate::management_v2_projection::signed(
            &self.core.config,
            &acceptance.source_approve_request,
            identity,
            &record.owner_ref,
            acceptance.pre_final_snapshot_revision,
            ManagementProjectionBodyV2::Operation {
                operation: record.operation,
            },
            now,
        )
        .map(Some)
    }
}
