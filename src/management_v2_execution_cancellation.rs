use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, decode_endpoint_revocation_execution_cancel_request_strict,
};

use crate::{HostError, management_v2_handler::ManagementV2Handler};

impl ManagementV2Handler {
    pub(crate) fn cancel_pending_revocation_execution(
        &self,
        transport: &SignedRequest,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let request =
            decode_endpoint_revocation_execution_cancel_request_strict(&transport.payload)
                .map_err(|_| HostError::RequestInvalid)?;
        let EndpointManagementEvidenceV2::Cancel {
            identity_exchange, ..
        } = &request.cancel_envelope.evidence
        else {
            return Err(HostError::RequestInvalid);
        };
        if !crate::management_v2_historic_mapping::current(
            &self.core.config,
            identity_exchange,
            &request.prepared.opaque_owner_ref,
            &transport.peer.device_id,
        ) {
            return Err(HostError::EvidenceInvalid);
        }
        let (revision, cancellation) = self.journal.accept_execution_cancellation(
            &request,
            &transport.peer.device_id,
            &self.core.config,
            now,
        )?;
        crate::management_v2_execution_cancellation_response::refresh(
            &self.core.config,
            &cancellation,
            revision,
            now,
        )
    }
}
