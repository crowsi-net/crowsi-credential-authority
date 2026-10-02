use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointIndependentRevocationFinalizeRequestV1, ManagementOperationState,
    ManagementProjectionBodyV2, decode_endpoint_independent_revocation_finalize_request_strict,
    identity_evidence_from_exchange,
};

use crate::{
    HostError, management_v2_handler::ManagementV2Handler,
    management_v2_journal_independent_finalization::IndependentFinalizationEntry,
};

impl ManagementV2Handler {
    pub(crate) fn finalize_independent_revocation(
        &self,
        transport: &SignedRequest,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let request =
            decode_endpoint_independent_revocation_finalize_request_strict(&transport.payload)
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
            .accept_independent_final(&request, &transport.peer.device_id)?;
        if let IndependentFinalizationEntry::Record(record) = accepted
            && record.operation.state == ManagementOperationState::Unknown
        {
            self.execute_revocation(*record, &[], now)?;
        }
        self.independent_finalization_projection(&request, &transport.peer.device_id, now)
    }

    fn independent_finalization_projection(
        &self,
        request: &EndpointIndependentRevocationFinalizeRequestV1,
        peer: &str,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let (revision, entry) = self.journal.independent_finalization_view(request, peer)?;
        let (operation, owner, acceptance) = match &entry {
            IndependentFinalizationEntry::Record(value) => (
                &value.operation,
                &value.owner_ref,
                value.independent_revocation_finalization.as_ref(),
            ),
            IndependentFinalizationEntry::Tombstone(value) => (
                &value.operation,
                &value.owner_ref,
                value.independent_revocation_finalization.as_ref(),
            ),
        };
        let acceptance = acceptance.ok_or(HostError::StateInvalid)?;
        let identity = identity_evidence_from_exchange(&acceptance.accepted_identity_exchange)
            .map_err(|_| HostError::StateInvalid)?;
        crate::management_v2_projection::signed(
            &self.core.config,
            &acceptance.pre_final_request.approve_revocation_request,
            identity,
            owner,
            revision,
            ManagementProjectionBodyV2::Operation {
                operation: operation.clone(),
            },
            now,
        )
    }
}
