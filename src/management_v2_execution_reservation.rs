use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::decode_endpoint_revocation_execution_reserve_request_strict;

use crate::{HostError, management_v2_handler::ManagementV2Handler};

impl ManagementV2Handler {
    pub(crate) fn reserve_revocation_execution(
        &self,
        transport: &SignedRequest,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let request =
            decode_endpoint_revocation_execution_reserve_request_strict(&transport.payload)
                .map_err(|_| HostError::RequestInvalid)?;
        if let Some((revision, stored)) = self
            .journal
            .execution_reservation_view(&request, &transport.peer.device_id)?
        {
            if !crate::management_v2_historic_mapping::current(
                &self.core.config,
                &request.accepted_identity_exchange,
                &request.prepared.opaque_owner_ref,
                &transport.peer.device_id,
            ) {
                return Err(HostError::EvidenceInvalid);
            }
            return crate::management_v2_execution_reservation_response::refresh(
                &self.core.config,
                &stored,
                revision,
                now,
            );
        }
        let verified = crate::management_v2_identity::verify_direct(
            &self.core.config,
            &request.reservation_identity_exchange,
            &transport.peer.device_id,
            &request.prepared,
            true,
            now,
        )?;
        let request_digest = crowsi_credential_authority_contracts::endpoint_revocation_execution_reserve_request_digest(&request)
            .map_err(|_| HostError::RequestInvalid)?;
        let binding = format!("sha256:{request_digest}");
        let exchange_digest = crate::management_v2_journal_policy::exchange_digest(
            &request.reservation_identity_exchange,
        )?;
        let uses = identity_uses(&verified, &exchange_digest, &binding);
        let (revision, stored) = self.journal.accept_execution_reservation(
            &request,
            &transport.peer.device_id,
            &self.core.config,
            &uses,
            now,
        )?;
        crate::management_v2_execution_reservation_response::refresh(
            &self.core.config,
            &stored,
            revision,
            now,
        )
    }
}

fn identity_uses<'a>(
    verified: &'a crate::management_v2_identity::VerifiedManagementIdentity<'a>,
    exchange_digest: &'a str,
    binding: &'a str,
) -> [crate::management_v2_journal_update::EvidenceUse<'a>; 3] {
    let identity = verified.identity;
    [
        crate::management_v2_journal_update::EvidenceUse {
            kind: "identity_authority_exchange",
            id: exchange_digest,
            binding,
            expires_at_epoch_s: verified.identity_exchange.response.expires_at_epoch_s,
        },
        crate::management_v2_journal_update::EvidenceUse {
            kind: "identity_assertion_nonce",
            id: &identity.assertion.nonce,
            binding,
            expires_at_epoch_s: identity.assertion.expires_at_epoch_s,
        },
        crate::management_v2_journal_update::EvidenceUse {
            kind: "current_status_nonce",
            id: &identity.current_status.nonce,
            binding,
            expires_at_epoch_s: identity.current_status.expires_at_epoch_s,
        },
    ]
}
