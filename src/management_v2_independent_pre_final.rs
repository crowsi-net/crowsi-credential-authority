use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    ManagementOperationState, ManagementProjectionBodyV2,
    decode_endpoint_independent_revocation_pre_final_request_strict,
};

use crate::{HostError, management_v2_handler::ManagementV2Handler};

impl ManagementV2Handler {
    pub(crate) fn independent_revocation_pre_final(
        &self,
        transport: &SignedRequest,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let request =
            decode_endpoint_independent_revocation_pre_final_request_strict(&transport.payload)
                .map_err(|_| HostError::RequestInvalid)?;
        if let Some(response) =
            self.recover_independent_pre_final(&request, &transport.peer.device_id, now)?
        {
            return Ok(response);
        }
        let verified = crate::management_v2_identity::verify_direct(
            &self.core.config,
            &request.accepted_identity_exchange,
            &transport.peer.device_id,
            &request.prepared,
            false,
            now,
        )?;
        let mut record = self
            .journal
            .record(&verified.owner.opaque_owner_ref, &request.operation_id)?;
        if record.operation.state != ManagementOperationState::AwaitingApprovalUv
            || record.operation.state_revision != request.expected_state_revision
            || record.prepared != request.prepared
            || record.operation.actor.required_actor_device_ref.as_deref()
                != Some(&transport.peer.device_id)
        {
            return Err(HostError::StateInvalid);
        }
        let approval = crate::management_v2_evidence::approval(
            &self.core.config,
            verified.owner,
            &request.selected_identity_exchange,
            &request.begin_uv_exchange,
            &request.finish_uv_exchange,
            &request.accepted_identity_exchange,
            &request.prepared,
            &request.approve_revocation_request.command,
            now,
        )?;
        crate::management_v2_evidence::independent_pre_final_ceremony(
            &self.core.config,
            &request.revocation_ceremony,
            now,
        )?;
        crate::management_v2_independent_pre_final_mutation::apply(
            self,
            &request,
            &verified,
            &approval.fresh_uv,
            &mut record,
            now,
        )
    }

    fn recover_independent_pre_final(
        &self,
        request: &crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1,
        peer: &str,
        now: u64,
    ) -> Result<Option<Vec<u8>>, HostError> {
        let Some((revision, record)) = self.journal.independent_pre_final_view(request, peer)?
        else {
            return Ok(None);
        };
        let acceptance = record
            .independent_revocation_finalization
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
        let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(
            &acceptance.accepted_identity_exchange,
        )
        .map_err(|_| HostError::StateInvalid)?;
        crate::management_v2_projection::signed(
            &self.core.config,
            &acceptance.pre_final_request.approve_revocation_request,
            identity,
            &record.owner_ref,
            revision,
            ManagementProjectionBodyV2::Operation {
                operation: record.operation,
            },
            now,
        )
        .map(Some)
    }
}
