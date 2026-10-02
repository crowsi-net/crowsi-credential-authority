use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointRevocationFinalizeRequestV1, ManagementOperationState, ManagementProjectionBodyV2,
    decode_endpoint_revocation_finalize_request_strict, identity_evidence_from_exchange,
};

use crate::{
    HostError, management_v2_handler::ManagementV2Handler,
    management_v2_journal_finalization::FinalizationEntry,
};

impl ManagementV2Handler {
    pub(crate) fn finalize_revocation(
        &self,
        transport: &SignedRequest,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let request = decode_endpoint_revocation_finalize_request_strict(&transport.payload)
            .map_err(|_| HostError::RequestInvalid)?;
        if !crate::management_v2_historic_mapping::current(
            &self.core.config,
            &request.accepted_identity_exchange,
            &request.prepared.opaque_owner_ref,
            &transport.peer.device_id,
        ) {
            return Err(HostError::EvidenceInvalid);
        }
        let accepted = self
            .journal
            .accept_revocation_final(&request, &transport.peer.device_id)?;
        if let FinalizationEntry::Record(record) = accepted
            && record.operation.state == ManagementOperationState::Unknown
        {
            self.execute_revocation(*record, &[], now)?;
        }
        self.finalization_projection(&request, &transport.peer.device_id, now)
    }

    fn finalization_projection(
        &self,
        request: &EndpointRevocationFinalizeRequestV1,
        peer: &str,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let (ledger_revision, entry) = self.journal.finalization_view(request, peer)?;
        let (operation, owner, acceptance) = match &entry {
            FinalizationEntry::Record(value) => (
                &value.operation,
                &value.owner_ref,
                value.revocation_finalization.as_ref(),
            ),
            FinalizationEntry::Tombstone(value) => (
                &value.operation,
                &value.owner_ref,
                value.revocation_finalization.as_ref(),
            ),
        };
        let acceptance = acceptance.ok_or(HostError::StateInvalid)?;
        let identity = identity_evidence_from_exchange(&acceptance.accepted_identity_exchange)
            .map_err(|_| HostError::StateInvalid)?;
        let digest = crowsi_credential_authority_contracts::management_command_digest(
            &acceptance.source_approve_request,
        )
        .map_err(|_| HostError::RequestInvalid)?;
        crate::management_v2_projection::signed_bound(
            &self.core.config,
            &acceptance.source_approve_request.request_id,
            digest,
            identity,
            owner,
            ledger_revision,
            ManagementProjectionBodyV2::Operation {
                operation: operation.clone(),
            },
            now,
        )
    }
}
