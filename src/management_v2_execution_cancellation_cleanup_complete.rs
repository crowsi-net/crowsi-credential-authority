use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2,
    decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict,
};

use crate::{HostError, management_v2_handler::ManagementV2Handler};

impl ManagementV2Handler {
    pub(crate) fn complete_pending_revocation_cancellation_cleanup(
        &self,
        transport: &SignedRequest,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let request = Box::new(
            decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict(
                &transport.payload,
            )
            .map_err(|_| HostError::RequestInvalid)?,
        );
        let EndpointManagementEvidenceV2::Cancel {
            identity_exchange, ..
        } = &request
            .cancel_finalize_request
            .cancellation_request
            .cancel_envelope
            .evidence
        else {
            return Err(HostError::RequestInvalid);
        };
        if !crate::management_v2_historic_mapping::current(
            &self.core.config,
            identity_exchange,
            &request
                .cancel_finalize_request
                .cancellation_request
                .prepared
                .opaque_owner_ref,
            &transport.peer.device_id,
        ) {
            return Err(HostError::EvidenceInvalid);
        }
        let (revision, completed) = self.journal.complete_execution_cancellation_cleanup(
            &request,
            &transport.peer.device_id,
            &self.core.config,
            now,
        )?;
        crate::management_v2_execution_cancellation_cleanup_complete_response::refresh(
            &self.core.config,
            &completed,
            revision,
            now,
        )
    }
}
