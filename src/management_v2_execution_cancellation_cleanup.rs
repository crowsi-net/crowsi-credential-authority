use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2,
    decode_endpoint_revocation_execution_cancel_finalize_request_strict,
};

use crate::{HostError, management_v2_handler::ManagementV2Handler};

impl ManagementV2Handler {
    pub(crate) fn acknowledge_pending_revocation_cancellation(
        &self,
        transport: &SignedRequest,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let request =
            decode_endpoint_revocation_execution_cancel_finalize_request_strict(&transport.payload)
                .map_err(|_| HostError::RequestInvalid)?;
        let EndpointManagementEvidenceV2::Cancel {
            identity_exchange, ..
        } = &request.cancellation_request.cancel_envelope.evidence
        else {
            return Err(HostError::RequestInvalid);
        };
        if !crate::management_v2_historic_mapping::current(
            &self.core.config,
            identity_exchange,
            &request.cancellation_request.prepared.opaque_owner_ref,
            &transport.peer.device_id,
        ) {
            return Err(HostError::EvidenceInvalid);
        }
        let (revision, cleanup) = self.journal.acknowledge_execution_cancellation(
            &request,
            &transport.peer.device_id,
            &self.core.config,
            now,
        )?;
        crate::management_v2_execution_cancellation_cleanup_response::refresh(
            &self.core.config,
            &cleanup,
            revision,
            now,
        )
    }
}
